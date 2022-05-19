/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.ssl.rest;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.security.action.sslreload.SSLReloadAction;
import org.opensearch.security.action.sslreload.SSLReloadRequest;
import org.opensearch.security.action.sslreload.SSLReloadResponse;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import static org.opensearch.rest.RestRequest.Method.PUT;


/**
 * Rest API action to reload SSL certificates.
 * Can be used to reload SSL certificates that are about to expire without restarting OpenSearch node.
 * This API assumes that new certificates are in the same location specified by the security configurations in opensearch.yml
 * (https://docs-beta.opensearch.org/docs/security-configuration/tls/)
 * To keep sensitive certificate reload secure, this API will only allow hot reload
 * with certificates issued by the same Issuer and Subject DN and SAN with expiry dates after the current one.
 * Currently this action serves PUT request for /_opendistro/_security/ssl/http/reloadcerts or /_opendistro/_security/ssl/transport/reloadcerts endpoint
 */
public class SecuritySSLReloadCertsAction extends BaseRestHandler {
    private static final List<Route> routes = Collections.singletonList(
            new Route(PUT, "_opendistro/_security/api/ssl/{certType}/reloadcerts/")
    );

    protected Logger logger = LogManager.getLogger(getClass());
    private final Settings settings;
    private final SecurityKeyStore sks;
    private final ThreadContext threadContext;
    private final AdminDNs adminDns;
    private final Supplier<DiscoveryNodes> nodesInCluster;
    private final TransportService transportService;

    public SecuritySSLReloadCertsAction(final Settings settings,
                                        final RestController restController,
                                        final SecurityKeyStore sks,
                                        final ThreadPool threadPool,
                                        final AdminDNs adminDns,
                                        final Supplier<DiscoveryNodes> nodesInCluster,
                                        final TransportService transportService) {
        super();
        this.settings = settings;
        this.sks = sks;
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
        this.nodesInCluster = nodesInCluster;
        this.transportService = transportService;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    /**
     * PUT request to reload SSL Certificates.
     *
     * Sample request:
     * PUT _opendistro/_security/api/ssl/transport/reloadcerts
     * PUT _opendistro/_security/api/ssl/http/reloadcerts
     *
     * NOTE: No request body is required. We will assume new certificates are loaded in the paths specified in your opensearch.yml file
     * (https://docs-beta.opensearch.org/docs/security/configuration/tls/)
     *
     * Sample response:
     * { "message": "updated http certs" }
     *
     * @param request request to be served
     * @param client client
     * @throws IOException
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            final String certType = request.param("certType").toLowerCase().trim();
            final boolean disconnectAfterReload = request.paramAsBoolean("disconnectAfterReload", false);

            @Override
            public void accept(RestChannel channel) throws Exception {
                BytesRestResponse response = null;

                // Check for Super admin user
                final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                if(user ==null||!adminDns.isAdmin(user)) {
                    response = toJsonBytesRestResponse(channel,null, null, RestStatus.FORBIDDEN);
                } else {
                    try {
                        if (sks != null) {
                            switch (certType) {
                                case "http":
                                    sks.initHttpSSLConfig();
                                    response = toJsonBytesRestResponse(channel,"message", "updated http certs", RestStatus.OK);
                                    break;
                                case "transport":
                                    sks.initTransportSSLConfig();

                                    if(disconnectAfterReload) {
                                        final DiscoveryNodes nodes = nodesInCluster.get();

                                        //disconnect must happen from both sides
                                        //this node must disconnect from the other nodes
                                        //the other nodes must also disconnect from this node
                                        //after the connections are closed they will be automatically re-established

                                        //make the other nodes disconnect from this node
                                        client.execute(SSLReloadAction.INSTANCE, new SSLReloadRequest(transportService.getLocalNode().getId()), new RestResponseListener<SSLReloadResponse>(channel) {
                                            @Override
                                            public RestResponse buildResponse(SSLReloadResponse sslReloadResponse) throws Exception {

                                                //this node now disconnects from every other node
                                                nodes.forEach(n -> {
                                                    try {
                                                        transportService.disconnectFromNode(n);
                                                    } catch (Exception e) {
                                                        logger.error("Unable to disconnect from node {}", n.getId());
                                                    }
                                                });
                                                logger.info("Disconnected from {} nodes because of reloading SSL certificates", nodes.getSize() - 1);
                                                return toJsonBytesRestResponse(channel,"message", "updated transport certs and disconnected", RestStatus.OK);
                                            }
                                        });

                                        return;
                                    } else {
                                        response = toJsonBytesRestResponse(channel,"message", "updated transport certs", RestStatus.OK);
                                    }

                                    break;
                                default:
                                    response = toJsonBytesRestResponse(channel,"message", "invalid uri path, please use /_opendistro/_security/api/ssl/http/reload or " +
                                            "/_opendistro/_security/api/ssl/transport/reload", RestStatus.FORBIDDEN);
                                    break;
                            }
                        } else {
                            response = toJsonBytesRestResponse(channel,"message", "keystore is not initialized", RestStatus.INTERNAL_SERVER_ERROR);
                        }
                    } catch (final Exception e1) {
                        response = toJsonBytesRestResponse(channel,"error", e1.toString(), RestStatus.INTERNAL_SERVER_ERROR);
                    }
                }
                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "SSL Cert Reload Action";
    }

    private static BytesRestResponse toJsonBytesRestResponse(RestChannel channel, String name, String value, RestStatus restStatus) throws IOException {
        if(name == null || name.isEmpty()) {
            return new BytesRestResponse(restStatus, "");
        }

        XContentBuilder builder = channel.newBuilder();
        builder.startObject();
        builder.field(name, value);
        builder.endObject();
        return new BytesRestResponse(restStatus, builder);
    };
}

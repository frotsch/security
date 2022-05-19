/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.action.sslreload;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.BaseNodeRequest;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportSSLReloadAction
extends
        TransportNodesAction<SSLReloadRequest, SSLReloadResponse, TransportSSLReloadAction.NodeSSLReloadRequest, SSLReloadNodeResponse> {

    protected Logger logger = LogManager.getLogger(getClass());
    private final AdminDNs adminDns;

    @Inject
    public TransportSSLReloadAction(final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
                                    final ActionFilters actionFilters, final AdminDNs adminDns) {

        super(SSLReloadAction.NAME, threadPool, clusterService, transportService, actionFilters,
                SSLReloadRequest::new, TransportSSLReloadAction.NodeSSLReloadRequest::new,
                ThreadPool.Names.MANAGEMENT, SSLReloadNodeResponse.class);

        this.adminDns = adminDns;
    }

    public static class NodeSSLReloadRequest extends BaseNodeRequest {

        SSLReloadRequest request;

        public NodeSSLReloadRequest(StreamInput in) throws IOException{
            super(in);
            request = new SSLReloadRequest(in);
        }

        public NodeSSLReloadRequest(final SSLReloadRequest request) {
            this.request = request;
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }


    @Override
    protected SSLReloadResponse newResponse(SSLReloadRequest request, List<SSLReloadNodeResponse> responses,
                                                                                       List<FailedNodeException> failures) {
        return new SSLReloadResponse(this.clusterService.getClusterName(), responses, failures);

    }

    @Override
    protected NodeSSLReloadRequest newNodeRequest(final SSLReloadRequest request) {
        return new NodeSSLReloadRequest(request);
    }

    @Override
    protected SSLReloadNodeResponse newNodeResponse(StreamInput streamInput) throws IOException {
        return new SSLReloadNodeResponse(streamInput);
    }

    @Override
    protected SSLReloadNodeResponse nodeOperation(final NodeSSLReloadRequest request) {

        //admin only
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null || !adminDns.isAdmin(user)) {
            throw new OpenSearchSecurityException("forbidden");
        }

        final String initiatingNodeId = request.request.getInitiatingNodeId();

        //only disconnect if the initiation node is now our current node
        if(!initiatingNodeId.equals(transportService.getLocalNode().getId())) {
            final DiscoveryNode initiatingDiscoveryNode = clusterService.state().getNodes().get(initiatingNodeId);

            if (initiatingDiscoveryNode != null) {
                try {
                    transportService.disconnectFromNode(initiatingDiscoveryNode);
                    logger.info("Disconnected from node {} because of reloading SSL certificates", initiatingDiscoveryNode.getId());
                } catch (Exception e) {
                    logger.error(e);
                }
            }
        }

        return new SSLReloadNodeResponse(clusterService.localNode());
    }
}

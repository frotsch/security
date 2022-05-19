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

import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.io.stream.StreamInput;

public class SSLReloadNodeResponse extends BaseNodeResponse {
    public SSLReloadNodeResponse(DiscoveryNode node) {
        super(node);
    }

    public SSLReloadNodeResponse(StreamInput in) throws IOException {
        super(in);
    }

    public static SSLReloadNodeResponse readNodeResponse(StreamInput in) throws IOException {
        return new SSLReloadNodeResponse(in);
    }
}

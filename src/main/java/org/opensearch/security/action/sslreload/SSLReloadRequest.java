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

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

public class SSLReloadRequest extends BaseNodesRequest<SSLReloadRequest> {

    private String initiatingNodeId;

    public SSLReloadRequest(String initiatingNodeId) {
        //send to all nodes
        super(new String[0]);
        this.initiatingNodeId = initiatingNodeId;
    }

    public SSLReloadRequest(StreamInput in) throws IOException {
        super(in);
        this.initiatingNodeId = in.readString();
    }


    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(initiatingNodeId);
    }

    public String getInitiatingNodeId() {
        return initiatingNodeId;
    }

    @Override
    public ActionRequestValidationException validate() {
        if (initiatingNodeId == null || initiatingNodeId.isEmpty()) {
            return new ActionRequestValidationException();
        }
        return null;
    }
}

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

import org.opensearch.action.ActionType;

public class SSLReloadAction extends ActionType<SSLReloadResponse> {

    public static final SSLReloadAction INSTANCE = new SSLReloadAction();
    public static final String NAME = "cluster:admin/opendistro_security/sslreload";

    protected SSLReloadAction() {
        super(NAME, SSLReloadResponse::new);
    }
}

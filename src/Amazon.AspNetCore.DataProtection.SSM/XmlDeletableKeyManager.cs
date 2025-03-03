/*
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at

      http://www.apache.org/licenses/LICENSE-2.0

  or in the "license" file accompanying this file. This file is distributed
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
  express or implied. See the License for the specific language governing
  permissions and limitations under the License.
 */

using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading;

namespace Amazon.AspNetCore.DataProtection.SSM
{
#if NET9_0_OR_GREATER
    /// <summary>
    /// Extension of XmlKeyManager which supports key deletion.
    /// 
    /// <para>
    /// XmlKeyManager implements IKeyManager but doesn't have the declaration for implementing IDeletableKeyManager. 
    /// We created our wrapper to have the IDeletableKeyManager declaration. Refer https://github.com/dotnet/aspnetcore/discussions/60315 for more details.
    /// </para>
    /// </summary>
    internal class XmlDeletableKeyManager : IDeletableKeyManager
    {
        XmlKeyManager _xmlKeyManager;

        /// <summary>
        /// Initializes a new instance of XmlDeletableKeyManager class.
        /// </summary>
        /// <param name="keyManagementOptions"></param>
        /// <param name="activator"></param>
        public XmlDeletableKeyManager(IOptions<KeyManagementOptions> keyManagementOptions, IActivator activator)
        {
            _xmlKeyManager = new XmlKeyManager(keyManagementOptions, activator);
        }

        /// <inheritdoc/>
        public bool CanDeleteKeys => _xmlKeyManager.CanDeleteKeys;

        /// <inheritdoc/>
        public bool DeleteKeys(Func<IKey, bool> shouldDelete)
        {
            return _xmlKeyManager.DeleteKeys(shouldDelete);
        }

        #region IKeyManager implementation
        /// <inheritdoc/>
        public IKey CreateNewKey(DateTimeOffset activationDate, DateTimeOffset expirationDate)
        {
            return _xmlKeyManager.CreateNewKey(activationDate, expirationDate);
        }

        /// <inheritdoc/>
        public IReadOnlyCollection<IKey> GetAllKeys()
        {
            return _xmlKeyManager.GetAllKeys();
        }

        /// <inheritdoc/>
        public CancellationToken GetCacheExpirationToken()
        {
            return _xmlKeyManager.GetCacheExpirationToken();
        }

        /// <inheritdoc/>
        public void RevokeAllKeys(DateTimeOffset revocationDate, string reason = null)
        {
            _xmlKeyManager.RevokeAllKeys(revocationDate, reason);
        }

        /// <inheritdoc/>
        public void RevokeKey(Guid keyId, string reason = null)
        {
            _xmlKeyManager.RevokeKey(keyId, reason);
        }
        #endregion
    }
#endif
}

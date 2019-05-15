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
using System;
using System.Collections.Generic;
using System.Text;
using Amazon.SimpleSystemsManagement;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Optional parameters that can be specified to configure how DataProtection keys should be stored in the Parameter Store.
    /// </summary>
    public class PersistOptions
    {
        /// <summary>
        /// The KMS Key ID that you want to use to encrypt a parameter when you choose the SecureString data type. If you 
        /// don't specify a key ID, the system uses the default key associated with your AWS account.
        /// </summary>
        public string KMSKeyId { get; set; }

        /// <summary>
        /// Whether the store is allowed to create SNN parameters using the Advanced Tier pricing in case that the stored key is to big for standard tier.
        /// Standard tier maximum size is 4096 characters (4KB).
        /// </summary>
        public bool CanUseAdvancedTier { get; set; }
    }
}
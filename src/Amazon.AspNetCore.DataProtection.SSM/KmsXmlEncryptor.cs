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
using System.IO;
using System.Text;
using System.Xml.Linq;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// An <see cref="IXmlEncryptor"/> that encrypts XML elements using AWS KMS.
    /// </summary>
    public sealed class KmsXmlEncryptor : IXmlEncryptor
    {
        private readonly IAmazonKeyManagementService _kmsClient;
        private readonly string _keyId;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new instance of <see cref="KmsXmlEncryptor"/>.
        /// </summary>
        /// <param name="kmsClient">The KMS client.</param>
        /// <param name="keyId">The KMS key ID, ARN, alias name, or alias ARN.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        public KmsXmlEncryptor(IAmazonKeyManagementService kmsClient, string keyId, ILoggerFactory loggerFactory = null)
        {
            _kmsClient = kmsClient ?? throw new ArgumentNullException(nameof(kmsClient));
            _keyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
            _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<KmsXmlEncryptor>();
        }

        /// <inheritdoc/>
        public EncryptedXmlInfo Encrypt(XElement plaintextElement)
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));

            var plaintextStream = new MemoryStream(plaintextBytes);
            try
            {
                var response = _kmsClient.EncryptAsync(new EncryptRequest
                {
                    KeyId = _keyId,
                    Plaintext = plaintextStream
                }).GetAwaiter().GetResult();

                _logger.LogDebug("Encrypted DataProtection key using KMS key {KeyId}", _keyId);

                var ciphertextBase64 = Convert.ToBase64String(response.CiphertextBlob.ToArray());
                var encryptedElement = new XElement("encryptedKey",
                    new XComment(" This key is encrypted with AWS KMS. "),
                    new XElement("value", ciphertextBase64));

                return new EncryptedXmlInfo(encryptedElement, typeof(KmsXmlDecryptor));
            }
            finally
            {
                plaintextStream.Dispose();
            }
        }
    }
}

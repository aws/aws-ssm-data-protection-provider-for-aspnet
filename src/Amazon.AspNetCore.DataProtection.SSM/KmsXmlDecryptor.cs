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
using System.Xml.Linq;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// An <see cref="IXmlDecryptor"/> that decrypts XML elements using AWS KMS.
    /// </summary>
    public sealed class KmsXmlDecryptor : IXmlDecryptor
    {
        private readonly IAmazonKeyManagementService _kmsClient;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new instance of <see cref="KmsXmlDecryptor"/>.
        /// </summary>
        /// <param name="services">The service provider used to resolve <see cref="IAmazonKeyManagementService"/>.</param>
        public KmsXmlDecryptor(IServiceProvider services)
        {
            _kmsClient = services.GetRequiredService<IAmazonKeyManagementService>();
            var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
            _logger = loggerFactory.CreateLogger<KmsXmlDecryptor>();
        }

        /// <inheritdoc/>
        public XElement Decrypt(XElement encryptedElement)
        {
            var ciphertextBase64 = encryptedElement.Element("value")?.Value
                ?? throw new InvalidOperationException("The encrypted element does not contain a 'value' child element.");

            var ciphertextBytes = Convert.FromBase64String(ciphertextBase64);

            var ciphertextStream = new MemoryStream(ciphertextBytes);
            try
            {
                var response = _kmsClient.DecryptAsync(new DecryptRequest
                {
                    CiphertextBlob = ciphertextStream
                }).GetAwaiter().GetResult();

                _logger.LogDebug("Decrypted DataProtection key using AWS KMS");

                var reader = new StreamReader(response.Plaintext);
                try
                {
                    var xml = reader.ReadToEnd();
                    return XElement.Parse(xml);
                }
                finally
                {
                    reader.Dispose();
                }
            }
            finally
            {
                ciphertextStream.Dispose();
            }
        }
    }
}

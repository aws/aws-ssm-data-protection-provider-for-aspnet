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

using Xunit;

using Moq;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.SimpleSystemsManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using System.IO;
using System.Xml.Linq;
using Amazon.SimpleSystemsManagement.Model;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Amazon.AspNetCore.DataProtection.SSM.Tests
{
    public class ExtensionMethodsTests
    {
        [Fact]
        public void RegisterSSMProvider()
        {
            var ssmClient = CreateMockSSMClient(null);

            var serviceContainer = new ServiceCollection()
                    .AddSingleton<IAmazonSimpleSystemsManagement>(ssmClient);

            serviceContainer.AddDataProtection()
                .PersistKeysToAWSSystemsManager("/RegisterTest");

            AssertDataProtectUnprotect(serviceContainer.BuildServiceProvider());
        }

        [Fact]
        public void RegisterSSMProviderWithKMSKey()
        {
            var kmsKeyId = "the-kms-key-id";
            var ssmClient = CreateMockSSMClient(kmsKeyId);

            var serviceContainer = new ServiceCollection()
                    .AddSingleton<IAmazonSimpleSystemsManagement>(ssmClient);

            serviceContainer.AddDataProtection()
                .PersistKeysToAWSSystemsManager("/RegisterTest", options =>
                {
                    options.KMSKeyId = kmsKeyId;
                });

            AssertDataProtectUnprotect(serviceContainer.BuildServiceProvider());
        }

#if NET9_0_OR_GREATER
        [Fact]
        public void CheckXmlDeletableKeyManager()
        {
            var serviceContainer = new ServiceCollection();

            serviceContainer.AddDataProtection()
                .PersistKeysToAWSSystemsManager("/MyApplication/DataProtection");

            var serviceProvider = serviceContainer.BuildServiceProvider();
            var keyManager = serviceProvider.GetService<IKeyManager>();

            Assert.True(keyManager is IDeletableKeyManager);
            Assert.True((keyManager as IDeletableKeyManager).CanDeleteKeys);
        }
#endif

        [Fact]
        public void RegisterSSMProviderWithProtectKeysWithAwsKms()
        {
            var ssmClient = CreateMockSSMClient(null);
            var kmsClient = CreateMockKmsClient();

            var serviceContainer = new ServiceCollection()
                    .AddSingleton<IAmazonSimpleSystemsManagement>(ssmClient)
                    .AddSingleton<IAmazonKeyManagementService>(kmsClient);

            serviceContainer.AddDataProtection()
                .PersistKeysToAWSSystemsManager("/RegisterTest")
                .ProtectKeysWithAwsKms("arn:aws:kms:us-east-1:123456789012:key/test-key");

            var services = serviceContainer.BuildServiceProvider();

            // Verify the encryptor and decryptor are registered
            var encryptor = services.GetService<IXmlEncryptor>();
            Assert.NotNull(encryptor);
            Assert.IsType<KmsXmlEncryptor>(encryptor);

            var decryptor = services.GetService<IXmlDecryptor>();
            Assert.NotNull(decryptor);
            Assert.IsType<KmsXmlDecryptor>(decryptor);

            AssertDataProtectUnprotect(services);
        }

        [Fact]
        public void ProtectKeysWithAwsKmsThrowsOnNullBuilder()
        {
            Assert.Throws<ArgumentNullException>(() =>
                ExtensionMethods.ProtectKeysWithAwsKms(null, "key-id"));
        }

        [Fact]
        public void ProtectKeysWithAwsKmsThrowsOnNullKeyId()
        {
            var serviceContainer = new ServiceCollection();
            var builder = serviceContainer.AddDataProtection();

            Assert.Throws<ArgumentNullException>(() =>
                builder.ProtectKeysWithAwsKms(null));
        }

        private IAmazonKeyManagementService CreateMockKmsClient()
        {
            var mockKms = new Mock<IAmazonKeyManagementService>();

            mockKms.Setup(client => client.EncryptAsync(It.IsAny<EncryptRequest>(), It.IsAny<CancellationToken>()))
                .Returns((EncryptRequest request, CancellationToken token) =>
                {
                    // Simulate KMS encryption by just passing through the plaintext (for testing)
                    var plaintext = new byte[request.Plaintext.Length];
                    request.Plaintext.Read(plaintext, 0, plaintext.Length);
                    request.Plaintext.Position = 0;

                    return Task.FromResult(new EncryptResponse
                    {
                        CiphertextBlob = new MemoryStream(plaintext)
                    });
                });

            mockKms.Setup(client => client.DecryptAsync(It.IsAny<DecryptRequest>(), It.IsAny<CancellationToken>()))
                .Returns((DecryptRequest request, CancellationToken token) =>
                {
                    // Simulate KMS decryption by just passing through the ciphertext (for testing)
                    var ciphertext = new byte[request.CiphertextBlob.Length];
                    request.CiphertextBlob.Read(ciphertext, 0, ciphertext.Length);
                    request.CiphertextBlob.Position = 0;

                    return Task.FromResult(new DecryptResponse
                    {
                        Plaintext = new MemoryStream(ciphertext)
                    });
                });

            return mockKms.Object;
        }

        private IAmazonSimpleSystemsManagement CreateMockSSMClient(string kmsKeyId)
        {
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            var parameters = new List<Parameter>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    if(!string.IsNullOrEmpty(kmsKeyId))
                    {
                        Assert.Equal(kmsKeyId, request.KeyId);
                    }

                    parameters.Add(new Parameter
                    {
                        Name = request.Name,
                        Value = request.Value,
                        Type = request.Type                        
                    });
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Returns((GetParametersByPathRequest r, CancellationToken t) =>
                {
                    var response = new GetParametersByPathResponse
                    {
                        Parameters = parameters
                    };
                    return Task.FromResult(response);
                });

            return mockSSM.Object;
        }

        private static void AssertDataProtectUnprotect(ServiceProvider services)
        {
            var dataProtector = services.GetDataProtector("test-purpose");
            var testData = Guid.NewGuid().ToString();
            var encData = dataProtector.Protect(testData);
            var decData = dataProtector.Unprotect(encData);

            Assert.Equal(testData, decData);
        }
    }
}

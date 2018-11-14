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

using Amazon.SimpleSystemsManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using System.Xml.Linq;
using Amazon.SimpleSystemsManagement.Model;
using System.Threading;
using System.Threading.Tasks;

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

        [Fact]
        public void ThrowErrorWhenSSMNotConfigured()
        {
            var serviceContainer = new ServiceCollection();

            serviceContainer.AddDataProtection()
                .PersistKeysToAWSSystemsManager("/RegisterTest");

            Assert.Throws<SSMNotConfiguredException>(() =>
            {
                AssertDataProtectUnprotect(serviceContainer.BuildServiceProvider());
            });
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

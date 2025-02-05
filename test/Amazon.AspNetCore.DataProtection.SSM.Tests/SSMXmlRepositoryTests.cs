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
using System.Linq;
using System.Xml.Linq;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

using Moq;

using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using System.Collections.Generic;

namespace Amazon.AspNetCore.DataProtection.SSM.Tests
{
    public class SSMXmlRepositoryTests
    {
        private const string BasePrefix = "MockKeyHome";
        private Mock<IAmazonSimpleSystemsManagement> _mockSSM;

        public SSMXmlRepositoryTests()
        {
            _mockSSM = new Mock<IAmazonSimpleSystemsManagement>();
        }

        [Fact]
        public void AddKey()
        {
            var prefix = "/" + BasePrefix + "/";
            var keyText = "<key id=\"foo\"></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal(prefix + "bar", request.Name);

                    Assert.NotNull(request.Description);

                    Assert.NotNull(request.Value);
                    XElement parsed = XElement.Parse(request.Value);
                    Assert.NotNull(parsed);

                    Assert.Null(request.KeyId);

                    Assert.NotNull(request.Tags);
                    Assert.Empty(request.Tags);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void AddKeyWithTags()
        {
            var prefix = "/" + BasePrefix + "/";
            var keyText = "<key id=\"foo\"></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal(prefix + "bar", request.Name);

                    Assert.NotNull(request.Description);

                    Assert.NotNull(request.Value);
                    XElement parsed = XElement.Parse(request.Value);
                    Assert.NotNull(parsed);

                    Assert.Null(request.KeyId);

                    Assert.NotNull(request.Tags);
                    Assert.NotEmpty(request.Tags);
                    Assert.Equal(2, request.Tags.Count);
                    Assert.NotNull(request.Tags.Find(tag => tag.Key == "a"));
                    Assert.Equal("1", request.Tags.Find(tag => tag.Key == "a").Value);
                    Assert.NotNull(request.Tags.Find(tag => tag.Key == "b"));
                    Assert.Equal("2", request.Tags.Find(tag => tag.Key == "b").Value);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var options = new PersistOptions();
            options.Tags["a"] = "1";
            options.Tags["b"] = "2";

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, options, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void GetKeys()
        {
            var prefix = "/" + BasePrefix + "/";

            _mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Callback<GetParametersByPathRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Path);
                    Assert.Equal(prefix, request.Path);

                    Assert.True(request.WithDecryption);

                })
                .Returns((GetParametersByPathRequest r, CancellationToken token) =>
                {
                    var response = new GetParametersByPathResponse();
                    response.Parameters.Add(new Parameter
                    {
                        Name = prefix + "foo",
                        Type = ParameterType.SecureString,
                        Value = "<key id=\"foo\"></key>"
                    });
                    response.Parameters.Add(new Parameter
                    {
                        Name = prefix + "bar",
                        Type = ParameterType.SecureString,
                        Value = "<key id=\"bar\"></key>"
                    });
                    return Task.FromResult(response);
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            var elements = repository.GetAllElements();
            Assert.Equal(2, elements.Count);
            foreach (var key in elements)
            {
                Assert.NotNull(key);
            }
        }

        [Fact]
        public void EnsureValidKeysComebackEvenWhenOneIsInvalid()
        {
            var prefix = "/" + BasePrefix + "/";

            _mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Callback<GetParametersByPathRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Path);
                    Assert.Equal(prefix, request.Path);

                    Assert.True(request.WithDecryption);

                })
                .Returns((GetParametersByPathRequest r, CancellationToken token) =>
                {
                    var response = new GetParametersByPathResponse();
                    response.Parameters.Add(new Parameter
                    {
                        Name = prefix + "foo",
                        Type = ParameterType.SecureString,
                        Value = "<key id=\"foo\"></key>"
                    });
                    response.Parameters.Add(new Parameter
                    {
                        Name = prefix + "bar",
                        Type = ParameterType.SecureString,
                        Value = "<key id=\"bar\"></missing-endtag>"
                    });
                    return Task.FromResult(response);
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            var elements = repository.GetAllElements();
            Assert.Single(elements);
            Assert.NotNull(elements.FirstOrDefault(x => string.Equals(x.Attribute("id").Value, "foo")));
        }

        [Fact]
        public void PageGetKeys()
        {
            var prefix = "/" + BasePrefix + "/";

            int callCount = 0;
            _mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Callback<GetParametersByPathRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Path);
                    Assert.Equal(prefix, request.Path);

                    Assert.True(request.WithDecryption);

                    if (callCount == 1)
                    {
                        Assert.NotNull(request.NextToken);
                        Assert.Equal("NextPageToken", request.NextToken);
                    }

                })
                .Returns((GetParametersByPathRequest r, CancellationToken token) =>
                {
                    var response = new GetParametersByPathResponse();
                    if (callCount == 0)
                    {
                        response.Parameters.Add(new Parameter
                        {
                            Name = prefix + "foo",
                            Type = ParameterType.SecureString,
                            Value = "<key id=\"foo\"></key>"
                        });
                        response.Parameters.Add(new Parameter
                        {
                            Name = prefix + "bar",
                            Type = ParameterType.SecureString,
                            Value = "<key id=\"bar\"></key>"
                        });

                        response.NextToken = "NextPageToken";
                    }
                    else
                    {
                        response.Parameters.Add(new Parameter
                        {
                            Name = prefix + "pizza",
                            Type = ParameterType.SecureString,
                            Value = "<key id=\"pizza\"></key>"
                        });
                    }

                    callCount++;
                    return Task.FromResult(response);
                });


            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            var elements = repository.GetAllElements();

            Assert.Equal(2, callCount);
            Assert.Equal(3, elements.Count);
        }

        [Fact]
        public void ParameterPrefixMissingBeginningSlash()
        {
            var prefix = BasePrefix + "/";
            var keyText = "<key id=\"foo\"></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal("/" + prefix + "bar", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void ParameterPrefixMissingEndingSlash()
        {
            var prefix = "/" + BasePrefix;
            var keyText = "<key id=\"foo\"></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal(prefix + "/bar", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void ParameterPrefixNoSlashes()
        {
            var keyText = "<key id=\"foo\"></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal("/" + BasePrefix + "/bar", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void ParameterUsesKeyId()
        {
            var keyText = "<key id=\"foo\"></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal("/" + BasePrefix + "/foo", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void ParameterUsesGuid()
        {
            var prefix = "MockKeyHome";
            var keyText = "<key></key>";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    var guidStr = request.Name.Substring(request.Name.LastIndexOf('/') + 1);

                    Assert.True(Guid.TryParse(guidStr, out _));
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void UseKMSKey()
        {
            var prefix = "/" + BasePrefix + "/";
            var keyText = "<key id=\"foo\"></key>";
            var kmsKeyId = "customer-provided-kms-key-id";

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal(prefix + "bar", request.Name);

                    Assert.NotNull(request.Description);

                    Assert.NotNull(request.Value);
                    XElement parsed = XElement.Parse(request.Value);
                    Assert.NotNull(parsed);

                    Assert.NotNull(request.KeyId);
                    Assert.Equal(kmsKeyId, request.KeyId);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var options = new PersistOptions
            {
                KMSKeyId = kmsKeyId
            };
            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, options, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void StorageModeStandardOnlyMaxSize()
        {
            var keyText = GenerateKeyOfLength(4096);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.Standard, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.StandardOnly
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void StorageModeStandardOnlyTooLarge()
        {
            var keyText = GenerateKeyOfLength(4096 + 1);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.StandardOnly
            }, null);

            XElement key = XElement.Parse(keyText);
            var ex = Assert.Throws<AggregateException>(() => repository.StoreElement(key, null));
            var ssmException = ex.InnerExceptions.SingleOrDefault(x => x.GetType() == typeof(SSMParameterToLongException));
            Assert.NotNull(ssmException);
        }

        [Fact]
        public void StorageModeAdvancedOnlyBelowAdvancedSize()
        {
            var keyText = GenerateKeyOfLength(4096);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.Advanced, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedOnly
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void StorageModeAdvancedOnlyMaxSize()
        {
            var keyText = GenerateKeyOfLength(8192);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.Advanced, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedOnly
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void StorageModeAdvancedOnlyTooLarge()
        {
            var keyText = GenerateKeyOfLength(8192 + 1);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedOnly
            }, null);

            XElement key = XElement.Parse(keyText);
            var ex = Assert.Throws<AggregateException>(() => repository.StoreElement(key, null));
            var ssmException = ex.InnerExceptions.SingleOrDefault(x => x.GetType() == typeof(SSMParameterToLongException));
            Assert.NotNull(ssmException);
        }

        [Fact]
        public void StorageModeAdvancedUpgradeableBelowAdvancedSize()
        {
            var keyText = GenerateKeyOfLength(4096);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.Standard, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedUpgradeable
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void StorageModeAdvancedUpgradeableAboveStandardSize()
        {
            var keyText = GenerateKeyOfLength(4096 + 1);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.Advanced, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedUpgradeable
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void StorageModeAdvancedUpgradeableMaxSize()
        {
            var keyText = GenerateKeyOfLength(8192);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.Advanced, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedUpgradeable
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void StorageModeAdvancedUpgradableTooLarge()
        {
            var keyText = GenerateKeyOfLength(8192 + 1);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.AdvancedUpgradeable
            }, null);

            XElement key = XElement.Parse(keyText);
            var ex = Assert.Throws<AggregateException>(() => repository.StoreElement(key, null));
            var ssmException = ex.InnerExceptions.SingleOrDefault(x => x.GetType() == typeof(SSMParameterToLongException));
            Assert.NotNull(ssmException);
        }

        [Fact]
        public void StorageModeIntelligentTiering()
        {
            var keyText = GenerateKeyOfLength(6000);

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.Equal(keyText, request.Value);
                    Assert.Equal(ParameterTier.IntelligentTiering, request.Tier);
                })
                .Returns((PutParameterRequest r, CancellationToken token) => Task.FromResult(new PutParameterResponse()));

            var repository = new SSMXmlRepository(_mockSSM.Object, BasePrefix, new PersistOptions
            {
                TierStorageMode = TierStorageMode.IntelligentTiering
            }, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

#if NET9_0_OR_GREATER
        [Fact]
        public void DeleteAllElementsTest()
        {
            var prefix = "/" + BasePrefix + "/";
            var parameters = new List<Parameter>();
            var friendlyNameKeyMap = new Dictionary<string, string>
            {
                { "bar1", "<key id=\"foo1\"></key>" },
                { "bar2", "<key id=\"foo2\"></key>" }
            };

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.StartsWith(prefix, request.Name);

                    Assert.NotNull(request.Description);

                    Assert.NotNull(request.Value);
                    XElement parsed = XElement.Parse(request.Value);
                    Assert.NotNull(parsed);

                    Assert.Null(request.KeyId);

                    Assert.True(request.Tags == null || request.Tags.Count == 0);

                    parameters.Add(new Parameter
                    {
                        Name = request.Name,
                        Type = ParameterType.SecureString,
                        Value = request.Value
                    });
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            _mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Callback<GetParametersByPathRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Path);
                    Assert.Equal(prefix, request.Path);

                    Assert.True(request.WithDecryption);

                })
                .Returns((GetParametersByPathRequest r, CancellationToken token) =>
                {
                    var response = new GetParametersByPathResponse();
                    response.Parameters = parameters;

                    return Task.FromResult(response);
                });

            _mockSSM.Setup(client => client.DeleteParameterAsync(It.IsAny<DeleteParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<DeleteParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.StartsWith(prefix, request.Name);
                })
                .Returns((DeleteParameterRequest r, CancellationToken token) =>
                {
                    var parameterToBeRemoved = parameters.First(p => p.Name == r.Name);
                    parameters.Remove(parameterToBeRemoved);
                    var response = new DeleteParameterResponse();
                    
                    return Task.FromResult(response);
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            foreach (var keyValuePair in friendlyNameKeyMap)
            {
                XElement key = XElement.Parse(keyValuePair.Value);
                repository.StoreElement(key, keyValuePair.Key);
            }

            var elements = repository.GetAllElements();
            Assert.Equal(2, elements.Count);

            var deleted = repository.DeleteElements((parameterCollection) =>
            {
                int deletionOrder = 0;
                foreach (var parameter in parameterCollection)
                {
                    parameter.DeletionOrder = deletionOrder;
                    deletionOrder++;
                }    
            });

            Assert.True(deleted);
            Assert.Empty(parameters);
        }

        [Fact]
        public void DeleteExceptionTest()
        {
            var prefix = "/" + BasePrefix + "/";
            var parameters = new List<Parameter>();
            var friendlyNameKeyMap = new Dictionary<string, string>
            {
                { "bar1", "<key id=\"foo1\"></key>" },
                { "bar_locked", "<key id=\"foo_locked\"></key>" },
                { "bar2", "<key id=\"foo2\"></key>" }
            };

            _mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.StartsWith(prefix, request.Name);

                    Assert.NotNull(request.Description);

                    Assert.NotNull(request.Value);
                    XElement parsed = XElement.Parse(request.Value);
                    Assert.NotNull(parsed);

                    Assert.Null(request.KeyId);

                    Assert.True(request.Tags == null || request.Tags.Count == 0);

                    parameters.Add(new Parameter
                    {
                        Name = request.Name,
                        Type = ParameterType.SecureString,
                        Value = request.Value
                    });
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            _mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Callback<GetParametersByPathRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Path);
                    Assert.Equal(prefix, request.Path);

                    Assert.True(request.WithDecryption);

                })
                .Returns((GetParametersByPathRequest r, CancellationToken token) =>
                {
                    var response = new GetParametersByPathResponse();
                    response.Parameters = parameters;

                    return Task.FromResult(response);
                });

            _mockSSM.Setup(client => client.DeleteParameterAsync(It.IsAny<DeleteParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<DeleteParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.StartsWith(prefix, request.Name);
                })
                .Returns((DeleteParameterRequest r, CancellationToken token) =>
                {
                    if (r.Name.EndsWith("bar_locked")) throw new InvalidOperationException($"Cannot delete locked parameter {r.Name}");

                    var parameterToBeRemoved = parameters.First(p => p.Name == r.Name);
                    parameters.Remove(parameterToBeRemoved);
                    var response = new DeleteParameterResponse();
                    
                    return Task.FromResult(response);
                });

            var repository = new SSMXmlRepository(_mockSSM.Object, prefix, null, null);

            foreach (var keyValuePair in friendlyNameKeyMap)
            {
                XElement key = XElement.Parse(keyValuePair.Value);
                repository.StoreElement(key, keyValuePair.Key);
            }

            var elements = repository.GetAllElements();
            Assert.Equal(3, elements.Count);

            var deleted = repository.DeleteElements((parameterCollection) =>
            {
                int deletionOrder = 0;
                foreach (var parameter in parameterCollection)
                {
                    parameter.DeletionOrder = deletionOrder;
                    deletionOrder++;
                }    
            });

            Assert.False(deleted);
            Assert.Equal(2, parameters.Count);
        }
#endif

        private string GenerateKeyOfLength(int length)
        {
            var start = "<key id=\"foo\">";
            var end = "</key>";
            var value = string.Empty;
            for (int i = 0; i < length - start.Length - end.Length; i++)
            {
                value += ".";
            }
            return start + value + end;
        }
    }
}

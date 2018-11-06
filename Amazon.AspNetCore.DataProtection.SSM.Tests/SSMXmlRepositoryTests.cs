using System;
using System.Linq;
using System.Xml.Linq;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

using Moq;

using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;

namespace Amazon.AspNetCore.DataProtection.SSM.Tests
{
    public class SSMXmlRepositoryTests
    {
        [Fact]
        public void AddKey()
        {
            var prefix = "/MockKeyHome/";
            var keyText = "<key id=\"foo\"></key>";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal(prefix + "bar", request.Name);

                    Assert.NotNull(request.Description);

                    Assert.NotNull(request.Value);
                    XElement parsed = XElement.Parse(request.Value);
                    Assert.NotNull(parsed);

                    Assert.Null(request.KeyId);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void GetKeys()
        {
            var prefix = "/MockKeyHome/";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
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

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            var elements = repository.GetAllElements();
            Assert.Equal(2, elements.Count);
            foreach(var key in elements)
            {
                Assert.NotNull(key);
            }
        }

        [Fact]
        public void EnsureValidKeysComebackEvenWhenOneIsInvalid()
        {
            var prefix = "/MockKeyHome/";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
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

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            var elements = repository.GetAllElements();
            Assert.Equal(1, elements.Count);
            Assert.NotNull(elements.FirstOrDefault(x => string.Equals(x.Attribute("id").Value, "foo")));
        }

        [Fact]
        public void PageGetKeys()
        {
            var prefix = "/MockKeyHome/";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            int callCount = 0;
            mockSSM.Setup(client => client.GetParametersByPathAsync(It.IsAny<GetParametersByPathRequest>(), It.IsAny<CancellationToken>()))
                .Callback<GetParametersByPathRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Path);
                    Assert.Equal(prefix, request.Path);

                    Assert.True(request.WithDecryption);

                    if(callCount == 1)
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


            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            var elements = repository.GetAllElements();

            Assert.Equal(2, callCount);
            Assert.Equal(3, elements.Count);
        }

        [Fact]
        public void ParameterPrefixMissingBeginningSlash()
        {
            var prefix = "MockKeyHome/";
            var keyText = "<key id=\"foo\"></key>";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal("/" + prefix + "bar", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void ParameterPrefixMissingEndingSlash()
        {
            var prefix = "/MockKeyHome";
            var keyText = "<key id=\"foo\"></key>";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal(prefix + "/bar", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void ParameterPrefixNoSlashes()
        {
            var prefix = "MockKeyHome";
            var keyText = "<key id=\"foo\"></key>";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal("/" + prefix + "/bar", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");
        }

        [Fact]
        public void ParameterUsesKeyId()
        {
            var prefix = "MockKeyHome";
            var keyText = "<key id=\"foo\"></key>";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
                .Callback<PutParameterRequest, CancellationToken>((request, token) =>
                {
                    Assert.NotNull(request.Name);
                    Assert.Equal("/" + prefix + "/foo", request.Name);
                })
                .Returns((PutParameterRequest r, CancellationToken token) =>
                {
                    return Task.FromResult(new PutParameterResponse());
                });

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void ParameterUsesGuid()
        {
            var prefix = "MockKeyHome";
            var keyText = "<key></key>";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
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

            var repository = new SSMXmlRepository(mockSSM.Object, prefix, null, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, null);
        }

        [Fact]
        public void UseKMSKey()
        {
            var prefix = "/MockKeyHome/";
            var keyText = "<key id=\"foo\"></key>";
            var kmsKeyId = "customer-provided-kms-key-id";
            var mockSSM = new Mock<IAmazonSimpleSystemsManagement>();

            mockSSM.Setup(client => client.PutParameterAsync(It.IsAny<PutParameterRequest>(), It.IsAny<CancellationToken>()))
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
            var repository = new SSMXmlRepository(mockSSM.Object, prefix, options, null);

            XElement key = XElement.Parse(keyText);
            repository.StoreElement(key, "bar");

        }
    }
}

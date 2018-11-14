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
using System.Xml.Linq;

using Microsoft.AspNetCore.DataProtection.Repositories;

using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Implementation of IXmlRepository that handles storing and retrieving DataProtection keys from the SSM Parameter Store. 
    /// </summary>
    internal class SSMXmlRepository : IXmlRepository, IDisposable
    {
        private readonly IAmazonSimpleSystemsManagement _ssmClient;
        private readonly string _parameterNamePrefix;
        private readonly PersistOptions _options;
        private readonly ILogger<SSMXmlRepository> _logger;

        /// <summary>
        /// Create an SSMXmlRepository
        /// 
        /// This class is internal and the constructor isn't meant to be called outside this assembly.
        /// It's used by the IDataProtectionBuilder.PersistKeysToAWSSystemsManager extension method.
        /// </summary>
        /// <param name="ssmClient"></param>
        /// <param name="parameterNamePrefix"></param>
        /// <param name="options"></param>
        /// <param name="loggerFactory"></param>
        public SSMXmlRepository(IAmazonSimpleSystemsManagement ssmClient, string parameterNamePrefix, PersistOptions options = null, ILoggerFactory loggerFactory = null)
        {
            _ssmClient = ssmClient ?? throw new ArgumentNullException(nameof(ssmClient));
            _parameterNamePrefix = parameterNamePrefix ?? throw new ArgumentNullException(nameof(parameterNamePrefix));
            _options = options ?? new PersistOptions();

            if(loggerFactory != null)
            {
                _logger = loggerFactory?.CreateLogger<SSMXmlRepository>();
            }
            else
            {
                _logger = NullLoggerFactory.Instance.CreateLogger<SSMXmlRepository>();
            }

            // make sure _parameterNamePrefix is bookended with '/' characters
            _parameterNamePrefix = '/' + _parameterNamePrefix.Trim('/') + '/';

            _logger.LogInformation($"Using SSM Parameter Store to persist DataProtection keys with parameter name prefix {_parameterNamePrefix}");
        }



        /// <summary>
        /// Get all of the DataProtection keys from parameter store. Any parameter values that can't be parsed 
        /// as XML, the format of DataProtection keys, will not be returned.
        /// </summary>
        /// <returns></returns>
        public IReadOnlyCollection<XElement> GetAllElements()
        {
            return Task.Run(GetAllElementsAsync).GetAwaiter().GetResult();
        }

        private async Task<IReadOnlyCollection<XElement>> GetAllElementsAsync()
        {
            var request = new GetParametersByPathRequest
            {
                Path = _parameterNamePrefix,
                WithDecryption = true
            };
            GetParametersByPathResponse response = null;

            var results = new List<XElement>();
            do
            {
                request.NextToken = response?.NextToken;
                try
                {
                    response = await _ssmClient.GetParametersByPathAsync(request);
                }
                catch(Exception e)
                {
                    _logger.LogError($"Error calling SSM to get parameters starting with {_parameterNamePrefix}: {e.Message}");
                    throw;
                }

                foreach(var parameter in response.Parameters)
                {
                    try
                    {
                        var xml = XElement.Parse(parameter.Value);
                        results.Add(xml);
                    }
                    catch(Exception e)
                    {
                        _logger.LogError($"Error parsing key {parameter.Name}, key will be skipped: {e.Message}");
                    }
                }

            } while(!string.IsNullOrEmpty(response.NextToken));

            _logger.LogInformation($"Loaded {results.Count} DataProtection keys");
            return results;
        }

        /// <summary>
        /// Stores the DataProtection key as parameter in SSM's parameter store. The parameter type will be set to SecureString.
        /// </summary>
        /// <param name="element"></param>
        /// <param name="friendlyName"></param>
        public void StoreElement(XElement element, string friendlyName)
        {
            Task.Run(() => StoreElementAsync(element, friendlyName)).Wait();
        }

        private async Task StoreElementAsync(XElement element, string friendlyName)
        {
            var parameterName = _parameterNamePrefix + 
                            (friendlyName ??
                            element.Attribute("id")?.Value ??
                            Guid.NewGuid().ToString());

            try
            {
                var request = new PutParameterRequest
                {
                    Name = parameterName,
                    Value = element.ToString(),
                    Type = ParameterType.SecureString,
                    Description = "ASP.NET Core DataProtection Key"
                };

                if(!string.IsNullOrEmpty(_options.KMSKeyId))
                {
                    request.KeyId = _options.KMSKeyId;
                }

                await _ssmClient.PutParameterAsync(request);

                _logger.LogInformation($"Saved DataProtection key to SSM Parameter Store with parameter name {parameterName}");
            }
            catch(Exception e)
            {
                _logger.LogError($"Error saving DataProtection key to SSM Parameter Store with parameter name {parameterName}: {e.Message}");
                throw;
            }
        }

        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _ssmClient?.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}

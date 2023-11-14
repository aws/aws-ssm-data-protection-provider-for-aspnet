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
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Amazon.Runtime;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Implementation of IXmlRepository that handles storing and retrieving DataProtection keys from the SSM Parameter Store. 
    /// </summary>
    internal class SSMXmlRepository : IXmlRepository, IDisposable
    {
        const string UserAgentHeader = "User-Agent";
        static readonly string _assemblyVersion = typeof(SSMXmlRepository).GetTypeInfo().Assembly.GetName().Version.ToString();

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

            AddUserAgentHandlerToClient(_ssmClient);

            if (loggerFactory != null)
            {
                _logger = loggerFactory?.CreateLogger<SSMXmlRepository>();
            }
            else
            {
                _logger = NullLoggerFactory.Instance.CreateLogger<SSMXmlRepository>();
            }

            // make sure _parameterNamePrefix is bookended with '/' characters
            _parameterNamePrefix = '/' + _parameterNamePrefix.Trim('/') + '/';

            _logger.LogInformation("Using SSM Parameter Store to persist DataProtection keys with parameter name prefix {ParameterNamePrefix}", _parameterNamePrefix);
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
                    response = await _ssmClient.GetParametersByPathAsync(request).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    _logger.LogError(
                        e,
                        "Error calling SSM to get parameters starting with {ParameterNamePrefix}: {ExceptionMessage}",
                        _parameterNamePrefix,
                        e.Message);

                    throw;
                }

                foreach (var parameter in response.Parameters)
                {
                    try
                    {
                        var xml = XElement.Parse(parameter.Value);
                        results.Add(xml);
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception e)
#pragma warning restore CA1031 // Do not catch general exception types
                    {
                        _logger.LogError(e, "Error parsing key {ParameterName}, key will be skipped: {ExceptionMessage}", parameter.Name, e.Message);
                    }
                }

            } while (!string.IsNullOrEmpty(response.NextToken));

            _logger.LogInformation("Loaded {Count} DataProtection keys", results.Count);
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

            var elementValue = element.ToString();
            var tier = GetParameterTier(elementValue);
            _logger.LogInformation("Using SSM parameter tier {Tier} for DataProtection element {ParameterName}", tier, parameterName);
            
            try
            {
                var request = new PutParameterRequest
                {
                    Name = parameterName,
                    Value = elementValue,
                    Type = ParameterType.SecureString,
                    Description = "ASP.NET Core DataProtection Key",
                    Tier = tier
                };

                if (_options.Tags?.Count > 0)
                {
                    request.Tags = _options.Tags
                        .Select(tag => new Tag() { Key = tag.Key, Value = tag.Value })
                        .ToList();
                }

                if (!string.IsNullOrEmpty(_options.KMSKeyId))
                {
                    request.KeyId = _options.KMSKeyId;
                }

                await _ssmClient.PutParameterAsync(request).ConfigureAwait(false);

                _logger.LogInformation("Saved DataProtection key to SSM Parameter Store with parameter name {ParameterName}", parameterName);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error saving DataProtection key to SSM Parameter Store with parameter name {ParameterName}: {ExceptionMessage}", parameterName, e.Message);
                throw;
            }
        }

        /// <summary>
        /// Gets the <see cref="ParameterTier"/> to use for the <paramref name="elementValue"/> based on the <paramref name="elementValue"/> length and configured <see cref="TierStorageMode"/>. 
        /// </summary>
        private ParameterTier GetParameterTier(string elementValue)
        { 
            var elementValueLength = elementValue.Length;
            var storageMode = _options.TierStorageMode;

            _logger.LogDebug("Using tier storage mode {StorageMode} to decide which SSM parameter tier to use for DataProtection element.", storageMode);

            // Check if the value is too large for the advanced tier (8192 characters/ 8KB), in this case the key generation is not suitable for keys that should be stored as SSM parameter.
            const int advancedTierMaxSize = 8192;
            if (elementValueLength > advancedTierMaxSize)
            { 
                throw new SSMParameterToLongException($"Could not save DataProtection element to SSM parameter. " +
                                                      $"DataProtection element has a length of {elementValueLength} which exceeds the maximum SSM parameter size of {advancedTierMaxSize}. " +
                                                      $"Please consider using another key provider or key store.");
            }

            // Check if advanced tier has to be used anyway due to tier storage mode
            if (storageMode == TierStorageMode.AdvancedOnly)
                return ParameterTier.Advanced;

            // Check if the value is too big for the standard tier and try to use the advanced tier if the storage mode allows it.
            // 4096 characters (4KB) is the maximum size for the standard tier.
            const int standardTierMaxSize = 4096;
            if (elementValueLength > standardTierMaxSize)
            {
                _logger.LogDebug("DataProtection element has a length of {Length} which exceeds the maximum standard tier SSM parameter size of {StandardTierMaxSize} (4KB), checking if advanced tier usage is allowed.", elementValueLength, standardTierMaxSize);

                // tier is too large for standard tier, check if advanced tier is allowed
                if (_options == null || _options.TierStorageMode == TierStorageMode.StandardOnly)
                { 
                    throw new SSMParameterToLongException($"Could not save DataProtection element to SSM parameter. " +
                                                          $"Element has {elementValueLength} characters which exceeds the limit of {standardTierMaxSize} characters of the standard parameter tier and usage of advanced tier is not configured." +
                                                          $"You can resolve this issue by changing the TierStorageMode to {nameof(TierStorageMode.AdvancedUpgradeable)} or {nameof(TierStorageMode.AdvancedOnly)} in the configuration.");
                }
 
                return ParameterTier.Advanced;
            }
             
            return ParameterTier.Standard;
        }

        #region IDisposable Support
        private bool disposedValue;

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

        private static void AddUserAgentHandlerToClient(IAmazonSimpleSystemsManagement iamazonSimpleSystemsManagement)
        {
            if (iamazonSimpleSystemsManagement is AmazonSimpleSystemsManagementClient amazonSimpleSystemsManagementClient)
            {
                amazonSimpleSystemsManagementClient.BeforeRequestEvent += (object sender, RequestEventArgs e) =>
                {
                    var args = e as WebServiceRequestEventArgs;
                    if (args == null || !args.Headers.ContainsKey(UserAgentHeader))
                        return;

                    args.Headers[UserAgentHeader] = args.Headers[UserAgentHeader] + " SSMDataProtectionProvider/" + _assemblyVersion;
                };
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Xml.Linq;

using Microsoft.AspNetCore.DataProtection.Repositories;

using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Implementation of IXmlRepository that handles storing and retrieving DataProtection keys from the SSM Parameter Store. 
    /// </summary>
    public class SSMXmlRepository : IXmlRepository, IDisposable
    {
        IAmazonSimpleSystemsManagement _ssmClient;
        string _parameterNamePrefix;
        private PersistOptions _options;
        ILogger<SSMXmlRepository> _logger;

        /// <summary>
        /// Instantiate an instance of SSMXmlRepository. The common usage is not to use this constructor directly but use the 
        /// extension method PersistKeysToAWSSystemsManager from the IDataProtectionBuilder. This will 
        /// take care of creating an instance of SSMXmlRepository and registering it as the xml repository for DataProtection.
        /// </summary>
        /// <param name="ssmClient"></param>
        /// <param name="parameterNamePrefix"></param>
        /// <param name="options"></param>
        /// <param name="loggerFactory"></param>
        public SSMXmlRepository(IAmazonSimpleSystemsManagement ssmClient, string parameterNamePrefix, PersistOptions options, ILoggerFactory loggerFactory)
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

            if (!this._parameterNamePrefix.StartsWith("/"))
            {
                this._parameterNamePrefix = "/" + this._parameterNamePrefix;
            }
            if (!this._parameterNamePrefix.EndsWith("/"))
            {
                this._parameterNamePrefix += "/";
            }

            this._logger.LogInformation($"Using SSM Parameter Store to persist DataProtection keys with parameter name prefix {this._parameterNamePrefix}");
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
                Path = this._parameterNamePrefix,
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
                    this._logger.LogError($"Error calling SSM to get parameters starting with {this._parameterNamePrefix}: {e.Message}");
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
                        this._logger.LogError($"Error parsing key {parameter.Name}, key will be skipped: {e.Message}");
                    }
                }

            }while(!string.IsNullOrEmpty(response.NextToken));

            this._logger.LogInformation($"Loaded {results.Count} DataProtection keys");
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
            var parameterName = this._parameterNamePrefix + 
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

                if(!string.IsNullOrEmpty(this._options.KMSKeyId))
                {
                    request.KeyId = this._options.KMSKeyId;
                }

                await this._ssmClient.PutParameterAsync(request);

                this._logger.LogInformation($"Saved DataProtection key to SSM Parameter Store with parameter name {parameterName}");
            }
            catch(Exception e)
            {
                this._logger.LogError($"Error saving DataProtection key to SSM Parameter Store with parameter name {parameterName}: {e.Message}");
                throw;
            }
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    this._ssmClient?.Dispose();
                }

                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}

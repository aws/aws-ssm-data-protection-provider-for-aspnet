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
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;

using Amazon.AspNetCore.DataProtection.SSM;
using Amazon.SimpleSystemsManagement;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods to make it easy to register SSM to persist data protection keys.
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// Register AWS Systems Manager (SSM) to persist the ASP.NET Core DataProtection framework keys. Keys will be stored in SSM's 
        /// Parameter Store using the prefix specified by the parameterNamePrefix parameter. It is expected that only DataProtection keys will be stored
        /// with this prefix.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="parameterNamePrefix">The prefix applied to the DataProtection key names.</param>
        /// <returns></returns>
        public static IDataProtectionBuilder PersistKeysToAWSSystemsManager(this IDataProtectionBuilder builder, string parameterNamePrefix)
        {
            return PersistKeysToAWSSystemsManager(builder, parameterNamePrefix, null);
        }

        /// <summary>
        /// Register AWS Systems Manager (SSM) to persist the ASP.NET Core DataProtection framework keys. Keys will be stored in SSM's 
        /// Parameter Store using the prefix specified by the parameterNamePrefix parameter. It is expected that only DataProtection keys will be stored
        /// with this prefix.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="parameterNamePrefix">The prefix applied to the DataProtection key names.</param>
        /// <param name="setupAction">Delegate to specify options for persistence. For example setting a KMS Key ID.</param>
        /// <returns></returns>
        public static IDataProtectionBuilder PersistKeysToAWSSystemsManager(this IDataProtectionBuilder builder, string parameterNamePrefix, Action<PersistOptions> setupAction)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(services =>
            {
                var ssmOptions = new PersistOptions();
                setupAction?.Invoke(ssmOptions);

                var ssmClient = services.GetService<IAmazonSimpleSystemsManagement>();
                if (ssmClient == null)
                {
                    throw new SSMNotConfiguredException();
                }

                var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
                return new ConfigureOptions<KeyManagementOptions>(options =>
                {
                    options.XmlRepository = new SSMXmlRepository(ssmClient, parameterNamePrefix, ssmOptions, loggerFactory);
                });
            });

            return builder;
        }
    }
}

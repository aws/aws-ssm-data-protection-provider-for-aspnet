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
using Amazon.AspNetCore.DataProtection.SSM;
using Amazon.KeyManagementService;
using Amazon.SimpleSystemsManagement;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System;

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
        public static IDataProtectionBuilder PersistKeysToAWSSystemsManager(this IDataProtectionBuilder builder, string parameterNamePrefix, Action<PersistOptions> setupAction = null)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.TryAddAWSService<IAmazonSimpleSystemsManagement>();

            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(services =>
            {
                var ssmOptions = new PersistOptions();
                setupAction?.Invoke(ssmOptions);

                var ssmClient = services.GetService<IAmazonSimpleSystemsManagement>();

                var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
                return new ConfigureOptions<KeyManagementOptions>(options =>
                {
                    options.XmlRepository = new SSMXmlRepository(ssmClient, parameterNamePrefix, ssmOptions, loggerFactory);
                });
            });

#if NET9_0_OR_GREATER
            builder.Services.AddSingleton<IKeyManager, XmlDeletableKeyManager>();
#endif

            return builder;
        }

        /// <summary>
        /// Configures the data protection system to protect keys with AWS KMS. This separates the encryption
        /// concern from the persistence concern, allowing you to use any persistence provider (SSM, Redis, 
        /// file system, etc.) while encrypting keys at rest with KMS.
        /// <para>
        /// When using this method with <see cref="PersistKeysToAWSSystemsManager(IDataProtectionBuilder, string)"/>, the SSM parameters will
        /// be stored as encrypted XML (encrypted by the Data Protection framework using KMS) rather than relying
        /// on SSM's SecureString parameter type.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="IDataProtectionBuilder"/>.</param>
        /// <param name="kmsKeyId">The KMS key ID, ARN, alias name, or alias ARN to use for encryption.</param>
        /// <returns>The <see cref="IDataProtectionBuilder"/>.</returns>
        /// <example>
        /// <code>
        /// // Use SSM for persistence and KMS for encryption (separated concerns)
        /// services.AddDataProtection()
        ///     .PersistKeysToAWSSystemsManager("/MyApp/DataProtection")
        ///     .ProtectKeysWithAwsKms("arn:aws:kms:us-east-1:123456789012:key/my-key-id");
        ///
        /// // Use Redis for persistence and KMS for encryption
        /// services.AddDataProtection()
        ///     .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys")
        ///     .ProtectKeysWithAwsKms("alias/my-data-protection-key");
        /// </code>
        /// </example>
        public static IDataProtectionBuilder ProtectKeysWithAwsKms(this IDataProtectionBuilder builder, string kmsKeyId)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }
            if (string.IsNullOrEmpty(kmsKeyId))
            {
                throw new ArgumentNullException(nameof(kmsKeyId));
            }

            builder.Services.TryAddAWSService<IAmazonKeyManagementService>();

            builder.Services.AddSingleton<IXmlEncryptor>(services =>
            {
                var kmsClient = services.GetRequiredService<IAmazonKeyManagementService>();
                var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
                return new KmsXmlEncryptor(kmsClient, kmsKeyId, loggerFactory);
            });

            builder.Services.AddSingleton<IXmlDecryptor, KmsXmlDecryptor>();

            return builder;
        }
    }
}

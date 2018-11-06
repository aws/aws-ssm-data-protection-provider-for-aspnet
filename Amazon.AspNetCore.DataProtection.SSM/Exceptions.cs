using System;
using System.Collections.Generic;
using System.Text;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Exception thrown when the service client for AWS Systems Manager, implementation of the interface IAmazonSimpleSystemsManagement,
    /// can not be found when constructing the DataProtection SSM repository. 
    /// </summary>
    public class SSMNotConfiguredException : Exception
    {
        /// <summary>
        /// Default Constructor
        /// </summary>
        public SSMNotConfiguredException()
            :base("The AWS Systems Manager service client is not configured with the service provider. " +
                  "Add the AWSSDK.Extensions.NETCore.Setup package and then call \"services.AddAWSService<Amazon.SimpleSystemsManagement.IAmazonSimpleSystemsManagement>();\" " +
                  "when adding services to the IServiceCollection.")
        {

        }
    }
}

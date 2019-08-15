using System;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Thrown when a parameter should be stored that exceeds the configured <see cref="PersistOptions.TierStorageMode"/>
    /// tiers maximum length.
    /// </summary>
    public class SSMParameterToLongException : Exception
    {
        public SSMParameterToLongException(string message) : base(message)
        {
        }
    }
}
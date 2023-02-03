using System;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Thrown when a parameter should be stored that exceeds the configured <see cref="PersistOptions.TierStorageMode"/>
    /// tiers maximum length.
    /// </summary>
#pragma warning disable CA1032 // Implement standard exception constructors
    public class SSMParameterToLongException : Exception
#pragma warning restore CA1032 // Implement standard exception constructors
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SSMParameterToLongException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public SSMParameterToLongException(string message) : base(message)
        {
        }
    }
}
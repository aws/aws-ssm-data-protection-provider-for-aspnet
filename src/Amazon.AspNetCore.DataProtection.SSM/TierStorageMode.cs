namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Mode to decide which parameter storage tier will be used.
    /// </summary>
    public enum TierStorageMode
    {
        /// <summary>
        /// Default. Will only use standard tier or fail if the value won't fit.
        /// </summary>
        StandardOnly,
        /// <summary>
        /// Use advanced tier if the value won't fit in standard tier.
        /// </summary>
        AdvancedUpgradeable, 
        /// <summary>
        /// Always use advanced tier.
        /// </summary>
        AdvancedOnly,
        /// <summary>
        /// Use IntelligentTiering
        /// </summary>
        IntelligentTiering
    }
}
namespace TwoFactorAuth.Net
{
    /// <summary>
    /// Specifies if a cryptographically secure RNG is required.
    /// </summary>
    /// <remarks>
    /// Since the RNG is only used to create a one-time created shared secret it is not *terribly* important to require
    /// a cryptographically secure RNG but it is ofcourse recommended to use a cryptographically secure RNG.
    /// </remarks>
    public enum CryptoSecureRequirement
    {
        /// <summary>Require a cryptographically secure RNG.</summary>
        RequireSecure,
        /// <summary>Allow non-cryptographically secure RNG.</summary>
        AllowInsecure
    }

    /// <summary>
    /// The algorithm to use for the TOTP.
    /// </summary>
    public enum Algorithm
    {
        /// <summary>SHA1</summary>
        SHA1,
        /// <summary>SHA256</summary>
        SHA256,
        /// <summary>SHA512</summary>
        SHA512,
        /// <summary>MD5</summary>
        MD5
    }
}

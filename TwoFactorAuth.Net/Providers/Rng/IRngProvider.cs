namespace TwoFactorAuth.Net.Providers.Rng
{
    /// <summary>
    /// Provides the interface for RNG (Random Number generator) providers.
    /// </summary>
    public interface IRngProvider
    {
        /// <summary>
        /// Gets whether the provider is cryptographically secure.
        /// </summary>
        /// <seealso cref="CryptoSecureRequirement"/>
        bool IsCryptographicallySecure { get; }

        /// <summary>
        /// Fills an array of bytes with a sequence of random values.
        /// </summary>
        /// <param name="bytes">The desired number of bytes to return.</param>
        /// <returns>An array with a sequence of random values.</returns>
        byte[] GetRandomBytes(int bytes);
    }
}

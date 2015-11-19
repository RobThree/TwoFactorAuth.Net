using System;

namespace TwoFactorAuth.Net.Providers.Rng
{
    /// <summary>
    /// Provides a non-cryptographically secure RNG provider.
    /// </summary>
    /// <remarks>
    /// The <see cref="PrngProvider"/> is based on a simple PRNG.
    /// </remarks>
    /// <seealso cref="IRngProvider"/>
    public class PrngProvider : IRngProvider
    {
        /// <summary>
        /// Gets whether the provider is cryptographically secure.
        /// </summary>
        /// <remarks>
        /// The <see cref="PrngProvider"/> is not cryptographically secure.
        /// </remarks>
        /// <seealso cref="CryptoSecureRequirement"/>
        public bool IsCryptographicallySecure { get { return false; } }

        /// <summary>
        /// Fills an array of bytes with a sequence of random values.
        /// </summary>
        /// <param name="bytes">The desired number of bytes to return.</param>
        /// <returns>An array with a sequence of random values.</returns>
        public byte[] GetRandomBytes(int bytes)
        {
            var buff = new byte[bytes];
            new Random().NextBytes(buff);
            return buff;
        }
    }
}

using System;
using System.Security.Cryptography;

namespace TwoFactorAuthNet.Providers.Rng;

/// <summary>
/// Provides a non-cryptographically secure RNG provider.
/// </summary>
/// <remarks>
/// The <see cref="PrngProvider"/> is based on a simple PRNG and iteratively (re)hashed values.
/// </remarks>
/// <seealso cref="IRngProvider"/>
public class HashRngProvider : IRngProvider
{
    private readonly HashAlgorithm _algorithm;

    /// <summary>
    /// Initializes a new instance of the <see cref="HashRngProvider"/> with a specified <see cref="HashAlgorithm"/>.
    /// </summary>
    /// <param name="algorithm">The <see cref="HashAlgorithm"/> to use when generating random number sequences.</param>
    public HashRngProvider(HashAlgorithm algorithm = null) => _algorithm = algorithm ?? HashAlgorithm.Create("HMACSHA256");

    /// <summary>
    /// Gets whether the provider is cryptographically secure.
    /// </summary>
    /// <remarks>
    /// The <see cref="HashRngProvider"/> is not cryptographically secure.
    /// </remarks>
    /// <seealso cref="CryptoSecureRequirement"/>
    public bool IsCryptographicallySecure => false;

    /// <summary>
    /// Fills an array of bytes with a sequence of random values.
    /// </summary>
    /// <param name="bytes">The desired number of bytes to return.</param>
    /// <returns>An array with a sequence of random values.</returns>
    public byte[] GetRandomBytes(int bytes)
    {
        var result = new byte[bytes];
        var hashbuff = new byte[_algorithm.HashSize / 8];
        var rng = new Random();

        for (var i = 0; i < bytes; i++)
        {
            rng.NextBytes(hashbuff);
            hashbuff = _algorithm.ComputeHash(hashbuff);
            result[i] = hashbuff[rng.Next(0, hashbuff.Length)];
        }
        return result;
    }
}

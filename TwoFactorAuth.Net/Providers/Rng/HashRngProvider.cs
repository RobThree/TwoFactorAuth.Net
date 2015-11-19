using System;
using System.Security.Cryptography;

namespace TwoFactorAuth.Net.Providers.Rng
{
    public class HashRngProvider : IRngProvider
    {
        private HashAlgorithm _algorithm;

        public HashRngProvider()
            : this(HashAlgorithm.Create("HMACSHA256"))
        { }

        public HashRngProvider(HashAlgorithm algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            _algorithm = algorithm;
        }

        public bool IsCryptographicallySecure
        {
            get { return false; }
        }

        public byte[] GetRandomBytes(int bytes)
        {
            var result = new byte[bytes];
            var hashbuff = new byte[_algorithm.HashSize / 8];
            var rng = new Random();

            for (int i = 0; i < bytes; i++)
            {
                rng.NextBytes(hashbuff);
                hashbuff = _algorithm.ComputeHash(hashbuff);
                result[i] = hashbuff[rng.Next(0, hashbuff.Length)];
            }
            return result;
        }
    }
}

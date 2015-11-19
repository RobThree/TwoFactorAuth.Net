using System;

namespace TwoFactorAuth.Net.Providers.Rng
{
    public class PrngProvider : IRngProvider
    {
        public bool IsCryptographicallySecure
        {
            get { return false; }
        }

        public byte[] GetRandomBytes(int bytes)
        {
            var buff = new byte[bytes];
            new Random().NextBytes(buff);
            return buff;
        }
    }
}

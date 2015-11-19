namespace TwoFactorAuth.Net.Providers.Rng
{
    public interface IRngProvider
    {
        bool IsCryptographicallySecure { get; }

        byte[] GetRandomBytes(int bytes);
    }
}

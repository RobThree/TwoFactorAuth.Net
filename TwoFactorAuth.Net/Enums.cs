namespace TwoFactorAuth.Net
{
    public enum CryptoSecureRequirement
    {
        RequireSecure,
        AllowInsecure
    }

    public enum Algorithm
    {
        SHA1,
        SHA256,
        SHA512,
        MD5
    }
}

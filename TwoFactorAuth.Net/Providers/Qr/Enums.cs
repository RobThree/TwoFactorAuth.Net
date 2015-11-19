namespace TwoFactorAuth.Net.Providers.Qr
{
    public enum ErrorCorrectionLevel
    {
        Low = 'L',
        Medium = 'M',
        Quartile = 'Q',
        High = 'H'
    }

    public enum SslPolicy
    {
        Verify,
        IgnoreErrors
    }
}

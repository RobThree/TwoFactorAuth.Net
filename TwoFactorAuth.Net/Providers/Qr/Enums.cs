namespace TwoFactorAuth.Net.Providers.Qr
{
    /// <summary>
    /// Specifies the desired Error Correction Level for the QR code.
    /// </summary>
    /// <see href="https://en.wikipedia.org/wiki/QR_code#Error_correction"/>
    public enum ErrorCorrectionLevel
    {
        /// <summary>Low, 7% of codewords can be restored.</summary>
        Low = 'L',
        /// <summary>Medium, 15% of codewords can be restored.</summary>
        Medium = 'M',
        /// <summary>Quartile, 25% of codewords can be restored.</summary>
        Quartile = 'Q',
        /// <summary>High, 30% of codewords can be restored.</summary>
        High = 'H'
    }

    /// <summary>
    /// Specifies the policy for connecting to SSL enabled hosts.
    /// </summary>
    public enum SslPolicy
    {
        /// <summary>Verify the SSQL certificate, throw on errors.</summary>
        Verify,
        /// <summary>Do not verify the SSQL certificate, ignore errors.</summary>
        IgnoreErrors
    }
}

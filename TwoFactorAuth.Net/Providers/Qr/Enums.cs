namespace TwoFactorAuthNet.Providers.Qr
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
}

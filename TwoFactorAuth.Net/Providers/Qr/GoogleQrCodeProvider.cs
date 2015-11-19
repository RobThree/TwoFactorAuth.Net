using System;

namespace TwoFactorAuth.Net.Providers.Qr
{
    // https://developers.google.com/chart/infographics/docs/qr_codes
    public class GoogleQrCodeProvider : BaseHttpQrCodeProvider, IQrCodeProvider
    {
        public ErrorCorrectionLevel ErrorCorrectionLevel { get; private set; }

        public int MarginRows { get; private set; }

        public GoogleQrCodeProvider()
            : this(ErrorCorrectionLevel.Low)
        { }

        public GoogleQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel)
            : this(errorCorrectionLevel, 1)
        { }

        public GoogleQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int marginRows)
            : this(errorCorrectionLevel, marginRows, SslPolicy.Verify)
        { }

        public GoogleQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int marginRows, SslPolicy sslPolicy)
            : base(sslPolicy)
        {
            if (!Enum.IsDefined(typeof(ErrorCorrectionLevel), errorCorrectionLevel))
                throw new ArgumentOutOfRangeException("errorCorrectionLevel");
            this.ErrorCorrectionLevel = errorCorrectionLevel;

            if (marginRows < 0)
                throw new ArgumentOutOfRangeException("marginRows");
            this.MarginRows = marginRows;
        }

        public byte[] GetQrCodeImage(string text, int size)
        {
            return this.DownloadData(this.GetUri(text, size));
        }

        private Uri GetUri(string qrText, int size)
        {
            return new Uri("https://chart.googleapis.com/chart?cht=qr"
                + "&chs=" + size + "x" + size
                + "&chld=" + (char)this.ErrorCorrectionLevel + "|" + this.MarginRows
                + "&chl=" + Uri.EscapeDataString(qrText)
            );
        }

        public string GetMimeType()
        {
            return "image/png";
        }
    }
}

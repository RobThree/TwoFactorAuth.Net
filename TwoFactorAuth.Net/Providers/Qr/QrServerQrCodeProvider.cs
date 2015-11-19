using System;
using System.Drawing;

namespace TwoFactorAuth.Net.Providers.Qr
{
    //TODO: implement charset-source / charset-target?

    // http://goqr.me/api/doc/create-qr-code/
    public class QrServerQrCodeProvider : BaseHttpQrCodeProvider, IQrCodeProvider
    {
        public enum QrServerImageFormat
        {
            Png,
            Gif,
            Jpeg,
            Svg,
            Eps
        }

        public ErrorCorrectionLevel ErrorCorrectionLevel { get; private set; }
        public Color BackgroundColor { get; private set; }
        public Color ForegroundColor { get; private set; }
        public int Margin { get; private set; }
        public int QuietZone { get; private set; }
        public QrServerImageFormat ImageFormat { get; private set; }

        public QrServerQrCodeProvider()
            : this(ErrorCorrectionLevel.Low)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel)
            : this(errorCorrectionLevel, 4)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int margin)
            : this(errorCorrectionLevel, margin, 1)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int margin, int quietZone)
            : this(errorCorrectionLevel, margin, quietZone, Color.White)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int margin, int quietZone, Color backgroundColor)
            : this(errorCorrectionLevel, margin, quietZone, backgroundColor, Color.Black)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int margin, int quietZone, Color backgroundColor, Color foregroundColor)
            : this(errorCorrectionLevel, margin, quietZone, backgroundColor, foregroundColor, QrServerImageFormat.Png)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int margin, int quietZone, Color backgroundColor, Color foregroundColor, QrServerImageFormat imageFormat)
            :this(errorCorrectionLevel, margin, quietZone, backgroundColor, foregroundColor, imageFormat, SslPolicy.Verify)
        { }

        public QrServerQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, int margin, int quietZone, Color backgroundColor, Color foregroundColor, QrServerImageFormat imageFormat, SslPolicy sslPolicy)
            : base(sslPolicy)
        {
            if (!Enum.IsDefined(typeof(ErrorCorrectionLevel), errorCorrectionLevel))
                throw new ArgumentOutOfRangeException("errorCorrectionLevel");
            this.ErrorCorrectionLevel = errorCorrectionLevel;

            if (margin < 0 || margin > 50)
                throw new ArgumentOutOfRangeException("margin");
            this.Margin = margin;

            if (quietZone < 0 || quietZone > 100)
                throw new ArgumentOutOfRangeException("quietZone");
            this.QuietZone = quietZone;

            this.BackgroundColor = backgroundColor;
            this.ForegroundColor = foregroundColor;

            if (!Enum.IsDefined(typeof(QrServerImageFormat), imageFormat))
                throw new ArgumentOutOfRangeException("imageFormat");
            this.ImageFormat = imageFormat;

        }

        public string GetMimeType()
        {
            switch (this.ImageFormat)
            {
                case QrServerImageFormat.Png:
                    return "image/png";
                case QrServerImageFormat.Gif:
                    return "image/gif";
                case QrServerImageFormat.Jpeg:
                    return "image/jpeg";
                case QrServerImageFormat.Svg:
                    return "image/svg+xml";
                case QrServerImageFormat.Eps:
                    return "application/postscript";
            }
            throw new InvalidOperationException("Unknown imageformat");
        }

        public byte[] GetQrCodeImage(string text, int size)
        {
            return this.DownloadData(this.GetUri(text, size));
        }

        private Uri GetUri(string qrText, int size)
        {
            return new Uri("https://api.qrserver.com/v1/create-qr-code/"
                + "?size=" + size + "x" + size
                + "&ecc=" + Char.ToUpperInvariant(((char)this.ErrorCorrectionLevel))
                + "&margin=" + this.Margin
                + "&qzone=" + this.QuietZone
                + "&bgcolor=" + Color2Hex(this.BackgroundColor)
                + "&color=" + Color2Hex(this.ForegroundColor)
                + "&format=" + Enum.GetName(typeof(QrServerImageFormat), this.ImageFormat).ToLowerInvariant()
                + "&data=" + Uri.EscapeDataString(qrText)
            );
        }
    }
}

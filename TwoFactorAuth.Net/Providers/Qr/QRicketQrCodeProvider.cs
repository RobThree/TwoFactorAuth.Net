using System;
using System.Drawing;

namespace TwoFactorAuth.Net.Providers.Qr
{
    // http://qrickit.com/qrickit_apps/qrickit_api.php
    public class QRicketQrCodeProvider : BaseHttpQrCodeProvider, IQrCodeProvider
    {
        public enum QRicketImageFormat
        {
            Png = 'p',
            Gif = 'g',
            Jpeg = 'j'
        }

        public ErrorCorrectionLevel ErrorCorrectionLevel { get; private set; }
        public Color BackgroundColor { get; private set; }
        public Color ForegroundColor { get; private set; }
        public QRicketImageFormat ImageFormat { get; private set; }

        private static readonly Uri baseuri = new Uri("http://qrickit.com/api/qr");

        public QRicketQrCodeProvider()
            : this(ErrorCorrectionLevel.Low)
        { }


        public QRicketQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel)
            : this(errorCorrectionLevel, Color.White)
        { }


        public QRicketQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, Color backgroundColor)
            : this(errorCorrectionLevel, backgroundColor, Color.Black)
        { }

        public QRicketQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, Color backgroundColor, Color foregroundColor)
            : this(errorCorrectionLevel, backgroundColor, foregroundColor, QRicketImageFormat.Png)
        { }


        public QRicketQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, Color backgroundColor, Color foregroundColor, QRicketImageFormat imageFormat)
            : this(errorCorrectionLevel, backgroundColor, foregroundColor, imageFormat, SslPolicy.Verify)
        { }

        public QRicketQrCodeProvider(ErrorCorrectionLevel errorCorrectionLevel, Color backgroundColor, Color foregroundColor, QRicketImageFormat imageFormat, SslPolicy sslPolicy)
            : base(baseuri, sslPolicy)
        {
            if (!Enum.IsDefined(typeof(ErrorCorrectionLevel), errorCorrectionLevel))
                throw new ArgumentOutOfRangeException("errorCorrectionLevel");
            this.ErrorCorrectionLevel = errorCorrectionLevel;

            this.BackgroundColor = backgroundColor;
            this.ForegroundColor = foregroundColor;

            if (!Enum.IsDefined(typeof(QRicketImageFormat), imageFormat))
                throw new ArgumentOutOfRangeException("imageFormat");
            this.ImageFormat = imageFormat;
        }

        public string GetMimeType()
        {
            switch (this.ImageFormat)
            {
                case QRicketImageFormat.Png:
                    return "image/png";
                case QRicketImageFormat.Gif:
                    return "image/gif";
                case QRicketImageFormat.Jpeg:
                    return "image/jpeg";
            }
            throw new InvalidOperationException("Unknown imageformat");
        }

        public byte[] GetQrCodeImage(string text, int size)
        {
            return this.DownloadData(this.GetUri(text, size));
        }

        private Uri GetUri(string qrText, int size)
        {
            return new Uri(this.BaseUri,
                "?qrsize=" + size
                + "&e=" + Char.ToLowerInvariant(((char)this.ErrorCorrectionLevel))
                + "&bgdcolor=" + Color2Hex(this.BackgroundColor)
                + "&fgdcolor=" + Color2Hex(this.ForegroundColor)
                + "&t=" + (char)this.ImageFormat
                + "&d=" + Uri.EscapeDataString(qrText)
            );
        }
    }
}

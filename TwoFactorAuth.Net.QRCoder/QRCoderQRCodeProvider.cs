using QRCoder;
using System;
using System.Drawing;
using TwoFactorAuthNet.Providers.Qr;

namespace TwoFactorAuthNet.QRCoder
{
    public class QRCoderQRCodeProvider : IQrCodeProvider
    {
        private readonly bool _forceutf8 = false;
        private readonly bool _utf8bom = false;
        private readonly int _requestedversion = -1;

        /// <summary>
        /// Gets the <see cref="TwoFactorAuthNet.Providers.Qr.ErrorCorrectionLevel"/> for the QR code.
        /// </summary>
        public ErrorCorrectionLevel ErrorCorrectionLevel { get; private set; }

        /// <summary>
        /// Gets the <see cref="EciMode"/> for the QR code.
        /// </summary>
        public EciMode EciMode { get; private set; }

        /// <summary>
        /// Gets the background color to be used for the QR code.
        /// </summary>
        public Color BackgroundColor { get; private set; }

        /// <summary>
        /// Gets the foreground color to be used for the QR code.
        /// </summary>
        public Color ForegroundColor { get; private set; }

        /// <summary>
        /// Initializes a new instance of a <see cref="QRCoderQRCodeProvider"/> with the specified
        /// <see cref="TwoFactorAuthNet.Providers.Qr.ErrorCorrectionLevel"/>, <see cref="BackgroundColor"/>, 
        /// <see cref="ForegroundColor"/> and  <see cref="EciMode">EciMode</see>.
        /// </summary>
        /// <param name="errorCorrectionLevel">The <see cref="TwoFactorAuthNet.Providers.Qr.ErrorCorrectionLevel"/> to use when generating QR codes.</param>
        /// <param name="backgroundColor">The background color to be used for the QR code.</param>
        /// <param name="foregroundColor">The foreground color to be used for the QR code.</param>
        /// <param name="eciMode">The <see cref="EciMode"/> to be used for the QR code.</param>
        public QRCoderQRCodeProvider(
            ErrorCorrectionLevel errorCorrectionLevel = ErrorCorrectionLevel.Low,
            Color? backgroundColor = null,
            Color? foregroundColor = null,
            EciMode eciMode = EciMode.Default)
        {
            if (!Enum.IsDefined(typeof(ErrorCorrectionLevel), errorCorrectionLevel))
                throw new ArgumentOutOfRangeException(nameof(errorCorrectionLevel));
            ErrorCorrectionLevel = errorCorrectionLevel;

            BackgroundColor = backgroundColor ?? Color.White;
            ForegroundColor = foregroundColor ?? Color.Black;

            if (!Enum.IsDefined(typeof(EciMode), eciMode))
                throw new ArgumentOutOfRangeException(nameof(eciMode));
            EciMode = eciMode;
        }

        /// <summary>
        /// Gets the MIME type of the image.
        /// </summary>
        /// <returns>Returns the MIME type of the image.</returns>
        /// <seealso cref="IQrCodeProvider"/>
        public string GetMimeType()
        {
            return "image/png";
        }

        /// <summary>
        /// Generates a QR code as image.
        /// </summary>
        /// <param name="text">The text to encode in the QR code.</param>
        /// <param name="size">The desired size (width and height equal) for the image.</param>
        /// <returns>Returns the binary representation of the image.</returns>
        /// <seealso cref="IQrCodeProvider"/>
        public byte[] GetQrCodeImage(string text, int size)
        {
            using (var generator = new QRCodeGenerator())
            using (var qrcodedata = generator.CreateQrCode(text, MapECCLevel(ErrorCorrectionLevel), _forceutf8, _utf8bom, MapEcimode(EciMode), _requestedversion))
            using (var qrcode = new PngByteQRCode(qrcodedata))
                return qrcode.GetGraphic(
                    (int)Math.Ceiling(size / (double)qrcodedata.ModuleMatrix.Count),
                    new[] { BackgroundColor.R, BackgroundColor.G, BackgroundColor.B },
                    new[] { ForegroundColor.R, ForegroundColor.G, ForegroundColor.B }
                );
        }

        private static QRCodeGenerator.ECCLevel MapECCLevel(ErrorCorrectionLevel eccLevel)
        {
            switch (eccLevel)
            {
                case ErrorCorrectionLevel.High:
                    return QRCodeGenerator.ECCLevel.H;
                case ErrorCorrectionLevel.Low:
                    return QRCodeGenerator.ECCLevel.L;
                case ErrorCorrectionLevel.Medium:
                    return QRCodeGenerator.ECCLevel.M;
                case ErrorCorrectionLevel.Quartile:
                    return QRCodeGenerator.ECCLevel.Q;
                default:
                    throw new ArgumentOutOfRangeException(nameof(eccLevel));
            }
        }

        private static QRCodeGenerator.EciMode MapEcimode(EciMode eciMode)
        {
            switch (eciMode)
            {
                case EciMode.Default:
                    return QRCodeGenerator.EciMode.Default;
                case EciMode.Iso8859_1:
                    return QRCodeGenerator.EciMode.Iso8859_1;
                case EciMode.Iso8859_2:
                    return QRCodeGenerator.EciMode.Iso8859_2;
                case EciMode.UTF8:
                    return QRCodeGenerator.EciMode.Utf8;
                default:
                    throw new ArgumentOutOfRangeException(nameof(eciMode));
            }
        }
    }

    public enum EciMode
    {
        Default,
        Iso8859_1,
        Iso8859_2,
        UTF8
    }
}

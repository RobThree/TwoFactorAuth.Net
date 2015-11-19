namespace TwoFactorAuth.Net.Providers.Qr
{
    /// <summary>
    /// Provides the interface for QR Code providers.
    /// </summary>
    public interface IQrCodeProvider
    {
        /// <summary>
        /// Downloads / retrieves / generates a QR code as image.
        /// </summary>
        /// <param name="text">The text to encode in the QR code.</param>
        /// <param name="size">The desired size (width and height equal) for the image.</param>
        /// <returns>Returns the binary representation of the image.</returns>
        /// <remarks>
        /// Images may under some circumstances be of a different size than the desired size depending on the QR code
        /// generator implementing the QR code generation.
        /// </remarks>
        byte[] GetQrCodeImage(string text, int size);

        /// <summary>
        /// Gets the MIME type of the image.
        /// </summary>
        /// <returns>Returns the MIME type of the image.</returns>
        /// <seealso href="https://www.iana.org/assignments/media-types/media-types.xhtml"/>
        string GetMimeType();
    }
}

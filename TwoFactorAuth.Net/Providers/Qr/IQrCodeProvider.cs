
namespace TwoFactorAuth.Net.Providers.Qr
{
    public interface IQrCodeProvider
    {
        byte[] GetQrCodeImage(string text, int size);
        string GetMimeType();
    }
}

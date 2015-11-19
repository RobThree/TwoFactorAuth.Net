using TwoFactorAuth.Net.Providers.Qr;
using TwoFactorAuth.Net.Providers.Rng;

namespace TwoFactorAuth.Net.Providers
{
    public class DefaultProviders
    {
        public static IRngProvider DefaultRngProvider { get { return new DefaultRngProvider(); } }
        public static IQrCodeProvider DefaultQrCodeProvider { get { return new GoogleQrCodeProvider(); } }

    }
}

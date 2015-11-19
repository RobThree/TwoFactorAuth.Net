using TwoFactorAuth.Net.Providers.Qr;
using TwoFactorAuth.Net.Providers.Rng;

namespace TwoFactorAuth.Net.Providers
{
    /// <summary>
    /// Provides default values for providers required by <see cref="TwoFactorAuth"/> instances.
    /// </summary>
    public class DefaultProviders
    {
        /// <summary>
        /// Gets the default RNG provider
        /// </summary>
        /// <seealso cref="IRngProvider"/>
        public static IRngProvider DefaultRngProvider { get { return new DefaultRngProvider(); } }

        /// <summary>
        /// Gets the default QR Code provider
        /// </summary>
        /// <seealso cref="IQrCodeProvider"/>
        public static IQrCodeProvider DefaultQrCodeProvider { get { return new GoogleQrCodeProvider(); } }

    }
}

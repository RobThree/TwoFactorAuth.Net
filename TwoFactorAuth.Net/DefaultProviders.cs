using TwoFactorAuthNet.Providers.Qr;
using TwoFactorAuthNet.Providers.Rng;
using TwoFactorAuthNet.Providers.Time;

namespace TwoFactorAuthNet
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
        public static IQrCodeProvider DefaultQrCodeProvider { get { return new QrServerQrCodeProvider(); } }

        /// <summary>
        /// Gets the default Time provider
        /// </summary>
        /// <seealso cref="ITimeProvider"/>
        public static ITimeProvider DefaultTimeProvider { get { return new LocalMachineTimeProvider(); } }

    }
}

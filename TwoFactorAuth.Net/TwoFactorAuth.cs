using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TwoFactorAuthNet.Providers.Qr;
using TwoFactorAuthNet.Providers.Rng;
using TwoFactorAuthNet.Providers.Time;

using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("TwoFactorAuth.Net.Tests")]

namespace TwoFactorAuthNet
{
    /// <summary>
    /// Provides methods to enable 2FA (Two Factor Authentication).
    /// </summary>
    /// <remarks>
    /// This library only provides the TOTP (Time-based One-time Password) implementation of 2FA. It does not provide
    /// a HOTP (HMAC-based One-time Password) implementation.
    /// </remarks>
    /// <seealso href="https://github.com/RobThree/TwoFactorAuth.Net"/>
    /// <seealso href="https://github.com/RobThree/TwoFactorAuth"/>
    /// <seealso href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format"/>
    public class TwoFactorAuth
    {
        private readonly Encoding ENCODING = Encoding.ASCII;
        private readonly DateTime EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Gets a string value indicating the provider or service this account is associated with.
        /// </summary>
        public string Issuer { get; private set; }

        /// <summary>
        /// Gets the number of digits to display to the user.
        /// </summary>
        /// <see cref="DEFAULTDIGITS"/>
        public int Digits { get; private set; }

        /// <summary>
        /// Gets the period that a TOTP code will be valid for, in seconds.
        /// </summary>
        /// <remarks>The period may be ignored by some 2FA client applications.</remarks>
        /// <see cref="DEFAULTPERIOD"/>
        public int Period { get; private set; }

        /// <summary>
        /// Gets the algorithm used for generating the TOTP codes.
        /// </summary>
        /// <remarks>The algorithm may be ignored by some 2FA client applications.</remarks>
        /// <see cref="DEFAULTALGORITHM"/>
        public Algorithm Algorithm { get; private set; }

        /// <summary>
        /// Gets the <see cref="IQrCodeProvider"/> to be used for generating QR codes.
        /// </summary>
        public IQrCodeProvider QrCodeProvider { get; private set; }

        /// <summary>
        /// Gets the <see cref="IRngProvider"/> to be used for generating random values.
        /// </summary>
        public IRngProvider RngProvider { get; private set; }

        /// <summary>
        /// Gets the <see cref="ITimeProvider"/> to be used when retrieving time information.
        /// </summary>
        public ITimeProvider TimeProvider { get; private set; }

        /// <summary>
        /// Defines the default number of digits used when this number is unspecified.
        /// </summary>
        public const int DEFAULTDIGITS = 6;

        /// <summary>
        /// Defines the default period used when the period is unspecified.
        /// </summary>
        public const int DEFAULTPERIOD = 30;

        /// <summary>
        /// Defines the default leniency used when ensuring correct time (see <see cref="EnsureCorrectTime(int)"/>).
        /// </summary>
        public const int DEFAULTLENIENCY = 5;

        /// <summary>
        /// Defines the default algorithm used when the algorithm is unspecified.
        /// </summary>
        public const Algorithm DEFAULTALGORITHM = Algorithm.SHA1;

        /// <summary>
        /// Defines the default discrepancy used when the discrepancy is unspecified.
        /// </summary>
        public const int DEFAULTDISCREPANCY = 1;

        /// <summary>
        /// Defines the default number of bits for entryp used when the number is unspecified.
        /// </summary>
        public const int DEFAULTSECRETBITS = 80;

        /// <summary>
        /// Defines the default QR code image size, in pixels, when the size is unspecified.
        /// </summary>
        public const int DEFAULTQRCODESIZE = 200;

        /// <summary>
        /// Intializes a new instance of the <see cref="TwoFactorAuth"/> class.
        /// </summary>
        public TwoFactorAuth()
            : this(null)
        { }

        /// <summary>
        /// Intializes a new instance of the <see cref="TwoFactorAuth"/> class.
        /// </summary>
        /// <param name="issuer">The issuer of the TOTP authentication token.</param>
        /// <param name="digits">The number of digits to be displayed to the user / required for verification.</param>
        /// <param name="period">The period, specified in seconds, a TOTP is valid.</param>
        /// <param name="algorithm">The algorithm to use when generating TOTP codes.</param>
        /// <param name="qrcodeprovider">The <see cref="IQrCodeProvider"/> to use for generating QR codes.</param>
        /// <param name="rngprovider">The <see cref="IRngProvider"/> to use for generating sequences of random numbers.</param>
        /// <param name="timeprovider">The <see cref="ITimeProvider"/> to use for generating sequences of random numbers.</param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when <paramref name="digits"/> or <paramref name="period"/> are less than 0 or the specified 
        /// <paramref name="algorithm"/> is invalid.
        /// </exception>
        public TwoFactorAuth(
            string issuer = null,
            int digits = DEFAULTDIGITS,
            int period = DEFAULTPERIOD,
            Algorithm algorithm = Algorithm.SHA1,
            IQrCodeProvider qrcodeprovider = null,
            IRngProvider rngprovider = null,
            ITimeProvider timeprovider = null)
        {
            Issuer = issuer;

            if (digits <= 0)
                throw new ArgumentOutOfRangeException(nameof(digits));
            Digits = digits;

            if (period <= 0)
                throw new ArgumentOutOfRangeException(nameof(period));
            Period = period;

            if (!Enum.IsDefined(typeof(Algorithm), algorithm))
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            Algorithm = algorithm;

            QrCodeProvider = qrcodeprovider ?? DefaultProviders.DefaultQrCodeProvider;
            RngProvider = rngprovider ?? DefaultProviders.DefaultRngProvider;
            TimeProvider = timeprovider ?? DefaultProviders.DefaultTimeProvider;
        }

        /// <summary>
        /// Creates a 80 bit secret key to be shared with the user on wich the future valid TOTP codes will be based. 
        /// The <see cref="CryptoSecureRequirement"/> is <see href="CryptoSecureRequirement.RequireSecure"/>.
        /// </summary>
        /// <returns>
        /// Returns a string of random values in 'Base32 alphabet' to be shared with the user / stored with the account.
        /// </returns>
        /// <seealso cref="DEFAULTSECRETBITS"/>
        public string CreateSecret()
        {
            return CreateSecret(DEFAULTSECRETBITS, CryptoSecureRequirement.RequireSecure);
        }

        /// <summary>
        /// Creates a secret key with the specified number of bits of entropy to be shared with the user on wich the
        /// future valid TOTP codes will be based. The <see cref="CryptoSecureRequirement"/> is 
        /// <see href="CryptoSecureRequirement.RequireSecure"/>.
        /// </summary>
        /// <param name="bits">The number of bits of entropy to use.</param>
        /// <returns>
        /// Returns a string of random values in 'Base32 alphabet' to be shared with the user / stored with the account.
        /// </returns>
        public string CreateSecret(int bits)
        {
            return CreateSecret(bits, CryptoSecureRequirement.RequireSecure);
        }

        /// <summary>
        /// Creates a secret key with the specified number of bits of entropy and specified 
        /// <see cref="CryptoSecureRequirement"/> to be shared with the user on wich the future valid TOTP codes will
        /// be based.
        /// </summary>
        /// <param name="bits">The number of bits of entropy to use.</param>
        /// <param name="cryptoSecureRequirement">The <see cref="CryptoSecureRequirement"/> to ensure cryptographically secure RNG's.</param>
        /// <returns>
        /// Returns a string of random values in 'Base32 alphabet' to be shared with the user / stored with the account.
        /// </returns>
        /// <exception cref="CryptographicException">
        /// Thrown when the <see cref="IRngProvider"/> of the instance is not cryptographically secure and the
        /// <see cref="CryptoSecureRequirement"/> requires a cryptographically secure RNG.
        /// </exception>
        public string CreateSecret(int bits, CryptoSecureRequirement cryptoSecureRequirement)
        {
            if (cryptoSecureRequirement == CryptoSecureRequirement.RequireSecure && !RngProvider.IsCryptographicallySecure)
                throw new CryptographicException("RNG provider is not cryptographically secure");

            int bytes = (int)Math.Ceiling((double)bits / 5);    // We use 5 bits of each byte (since we have a
                                                                // 32-character 'alphabet' / base32)

            // Note that we DO NOT actually "base32 encode" the random bytes, we simply take 5 bits from each random 
            // byte and map these directly to letters from the base32 alphabet (effectively 'base32 encoding on the fly').
            return string.Concat(RngProvider.GetRandomBytes(bytes).Select(v => Base32.Base32Alphabet[v & 31]));
        }

        /// <summary>
        /// Gets a TOTP code based on the specified secret for the current time.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <returns>Returns a TOTP code based on the specified secret for the current time.</returns>
        public string GetCode(string secret)
        {
            return GetCode(secret, GetTime());
        }

        /// <summary>
        /// Gets a TOTP code based on the specified secret for the specified <see cref="DateTime"/>.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="dateTime">The <see cref="DateTime"/> for the TOTP code.</param>
        /// <returns>Returns a TOTP code based on the specified secret for the specified <see cref="DateTime"/>.</returns>
        public string GetCode(string secret, DateTime dateTime)
        {
            return GetCode(secret, DateTimeToTimestamp(dateTime));
        }

        /// <summary>
        /// Gets a TOTP code based on the specified secret for the specified timestamp.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="timestamp">The timestamp for the TOTP code.</param>
        /// <returns>Returns a TOTP code based on the specified secret for the specified timestamp.</returns>
        public string GetCode(string secret, long timestamp)
        {
            using (var algo = (KeyedHashAlgorithm)CryptoConfig.CreateFromName("HMAC" + Enum.GetName(typeof(Algorithm), Algorithm)))
            {
                algo.Key = Base32.Decode(secret);
                var ts = BitConverter.GetBytes(GetTimeSlice(timestamp, 0));
                var hashhmac = algo.ComputeHash(new byte[] { 0, 0, 0, 0, ts[3], ts[2], ts[1], ts[0] });
                var offset = hashhmac[hashhmac.Length - 1] & 0x0F;
                return (((
                    hashhmac[offset + 0] << 24 |
                    hashhmac[offset + 1] << 16 |
                    hashhmac[offset + 2] << 8 |
                    hashhmac[offset + 3]
                ) & 0x7FFFFFFF) % (long)Math.Pow(10, Digits)).ToString().PadLeft(Digits, '0');
            }
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the current time and with a <see cref="DEFAULTDISCREPANCY"/>.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        public bool VerifyCode(string secret, string code)
        {
            return VerifyCode(secret, code, DEFAULTDISCREPANCY, out _);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the current time and with a <see cref="DEFAULTDISCREPANCY"/>.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="timeSlice">When this method returns, contains the timeslice that matched the code</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        public bool VerifyCode(string secret, string code, out long timeSlice)
        {
            return VerifyCode(secret, code, DEFAULTDISCREPANCY, out timeSlice);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the current time and with a specified discrepancy.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="discrepancy">The allowed time discrepancy (in both directions)  in number of <see cref="Period"/>s.</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        public bool VerifyCode(string secret, string code, int discrepancy)
        {
            return VerifyCode(secret, code, discrepancy, GetTime(), out _);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the current time and with a specified discrepancy.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="discrepancy">The allowed time discrepancy (in both directions)  in number of <see cref="Period"/>s.</param>
        /// <param name="timeSlice">When this method returns, contains the timeslice that matched the code</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        public bool VerifyCode(string secret, string code, int discrepancy, out long timeSlice)
        {
            return VerifyCode(secret, code, discrepancy, GetTime(), out timeSlice);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the specified <see cref="DateTime"/> and with a specified
        /// discrepancy.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="discrepancy">The allowed time discrepancy (in both directions)  in number of <see cref="Period"/>s.</param>
        /// <param name="dateTime">The <see cref="DateTime"/> for wich to verify the TOTP code.</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        public bool VerifyCode(string secret, string code, int discrepancy, DateTime dateTime)
        {
            return VerifyCode(secret, code, discrepancy, DateTimeToTimestamp(dateTime), out _);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the specified <see cref="DateTime"/> and with a specified
        /// discrepancy.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="discrepancy">The allowed time discrepancy (in both directions)  in number of <see cref="Period"/>s.</param>
        /// <param name="dateTime">The <see cref="DateTime"/> for wich to verify the TOTP code.</param>
        /// <param name="timeSlice">When this method returns, contains the timeslice that matched the code</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        public bool VerifyCode(string secret, string code, int discrepancy, DateTime dateTime, out long timeSlice)
        {
            return VerifyCode(secret, code, discrepancy, DateTimeToTimestamp(dateTime), out timeSlice);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the specified timestamp and with a specified discrepancy.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="discrepancy">The allowed time discrepancy (in both directions) in number of <see cref="Period"/>s.</param>
        /// <param name="timestamp">The timestamp for wich to verify the TOTP code.</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="secret"/> or <paramref name="code"/> is null.
        /// </exception>
        public bool VerifyCode(string secret, string code, int discrepancy, long timestamp)
        {
            return VerifyCode(secret, code, discrepancy, timestamp, out _);
        }

        /// <summary>
        /// Verifies a TOTP code with the shared secret for the specified timestamp and with a specified discrepancy.
        /// </summary>
        /// <param name="secret">The shared secret.</param>
        /// <param name="code">The TOTP code to verify.</param>
        /// <param name="discrepancy">The allowed time discrepancy (in both directions) in number of <see cref="Period"/>s.</param>
        /// <param name="timestamp">The timestamp for wich to verify the TOTP code.</param>
        /// <param name="timeSlice">When this method returns, contains the timeslice that matched the code</param>
        /// <returns>Returns true when the TOTP code is valid, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="secret"/> or <paramref name="code"/> is null.
        /// </exception>
        public bool VerifyCode(string secret, string code, int discrepancy, long timestamp, out long timeSlice)
        {
            if (secret == null)
                throw new ArgumentNullException(nameof(secret));
            if (code == null)
                throw new ArgumentNullException(nameof(code));

            // Make sure discrepancy is always positive
            discrepancy = Math.Abs(discrepancy);

            timeSlice = 0;

            // To keep safe from timing-attacks we iterate *all* possible codes even though we already may have
            // verified a code is correct. We use the timeSlice variable to hold either 0 (no match) or the timeslice
            // of the match. Each iteration we either set the timeslice variable to the timeslice of the match
            // or set the value to itself.  This is an effort to maintain constant execution time for the code.
            for (int i = -discrepancy; i <= discrepancy; i++)
            {
                var ts = timestamp + (i * Period);
                var slice = GetTimeSlice(ts, 0);
                timeSlice = CodeEquals(GetCode(secret, ts), code) ? slice : timeSlice;
            }

            return timeSlice > 0;
        }

        /// <summary>
        /// Retrieves / generates a QR code to be displayed to the user for sharing the shared secret and easy input
        /// of this code by scanning with a default size (<see cref="DEFAULTQRCODESIZE"/>).
        /// </summary>
        /// <param name="label">The label to identify which account a key is associated with.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns>Returns an image encoded as data uri.</returns>
        /// <see href="https://en.wikipedia.org/wiki/Data_URI_scheme"/>
        public string GetQrCodeImageAsDataUri(string label, string secret)
        {
            return GetQrCodeImageAsDataUri(label, secret, DEFAULTQRCODESIZE);
        }

        /// <summary>
        /// Retrieves / generates a QR code to be displayed to the user for sharing the shared secret and easy input
        /// of this code by scanning with a specified size.
        /// </summary>
        /// <param name="label">The label to identify which account a key is associated with.</param>
        /// <param name="secret">The shared secret.</param>
        /// <param name="size">The desired size, in pixels (width and height equal), of the QR code.</param>
        /// <returns>Returns an image encoded as data uri.</returns>
        /// <see href="https://en.wikipedia.org/wiki/Data_URI_scheme"/>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="size"/> is less than 0</exception>
        public string GetQrCodeImageAsDataUri(string label, string secret, int size)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size));

            return "data:"
                + QrCodeProvider.GetMimeType()
                + ";base64,"
                + Convert.ToBase64String(QrCodeProvider.GetQrCodeImage(GetQrText(label, secret), size));
        }

        /// <summary>
        /// Checks the <see cref="TwoFactorAuth"/>'s <see cref="TimeProvider"/> against a number of default built-in
        /// <see cref="ITimeProvider"/>s and throws when the time is off by more than the specified leniency. If this
        /// value exceeds the given leniency a <see cref="TimeProviderException"/> exception will be thrown.
        /// </summary>
        /// <param name="leniency">
        /// The number of seconds the current instance's <see cref="TimeProvider"/> is allowed to be off without
        /// throwing an exception.
        /// </param>
        /// <exception cref="TimeProviderException">
        /// Thrown when the current instance's <see cref="TimeProvider"/> is off by more than the specified leniency
        /// number of seconds.
        /// </exception>
        public void EnsureCorrectTime(int leniency = DEFAULTLENIENCY)
        {
            EnsureCorrectTime(new ITimeProvider[] {
                new NTPTimeProvider(),
                new HttpTimeProvider(),
            }, leniency);
        }

        /// <summary>
        /// Checks the <see cref="TwoFactorAuth"/>'s <see cref="TimeProvider"/> against given
        /// <see cref="ITimeProvider"/>s and throws when the time is off by more than the <see cref="DEFAULTLENIENCY"/>
        /// number of seconds. If this value exceeds the given leniency a <see cref="TimeProviderException"/> exception
        /// will be thrown.
        /// </summary>
        /// <param name="timeproviders">
        /// A collection of <see cref="ITimeProvider"/>s to check the current instance's <see cref="TimeProvider"/>
        /// against.
        /// </param>
        /// <exception cref="TimeProviderException">
        /// Thrown when the current instance's <see cref="TimeProvider"/> is off by more than the 
        /// <see cref="DEFAULTLENIENCY"/> number of seconds.
        /// </exception>
        public void EnsureCorrectTime(IEnumerable<ITimeProvider> timeproviders)
        {
            EnsureCorrectTime(timeproviders, DEFAULTLENIENCY);
        }

        /// <summary>
        /// Checks the <see cref="TwoFactorAuth"/>'s <see cref="TimeProvider"/> against given
        /// <see cref="ITimeProvider"/>s and throws when the time is off by more than the specified leniency. If this
        /// value exceeds the given leniency a <see cref="TimeProviderException"/> exception will be thrown.
        /// </summary>
        /// <param name="timeproviders">
        /// A collection of <see cref="ITimeProvider"/>s to check the current instance's <see cref="TimeProvider"/>
        /// against.
        /// </param>
        /// <param name="leniency">
        /// The number of seconds the current instance's <see cref="TimeProvider"/> is allowed to be off without
        /// throwing an exception.
        /// </param>
        /// <exception cref="TimeProviderException">
        /// Thrown when the current instance's <see cref="TimeProvider"/> is off by more than the specified leniency
        /// number of seconds.
        /// </exception>
        public void EnsureCorrectTime(IEnumerable<ITimeProvider> timeproviders, int leniency)
        {
            if (timeproviders == null)
                throw new ArgumentNullException(nameof(timeproviders));
            if (!timeproviders.Any())
                throw new ArgumentException(nameof(timeproviders));

            foreach (var t in timeproviders)
            {
                if (TimeSpan.FromTicks(Math.Abs((t.GetTimeAsync().Result - GetTime()).Ticks)) > TimeSpan.FromSeconds(leniency))
                    throw new TimeProviderException($"Time for timeprovider is off by more than {leniency} seconds when compared to {t.GetType().Name}");
            }
        }

        /// <summary>
        /// Calculates the timeslice (e.g. number of periods since <see cref="EPOCH"/>) for a given timestamp and
        /// offset (specified in number of periods).
        /// </summary>
        /// <param name="timestamp">The timestamp to calculate the timeslice for.</param>
        /// <param name="offset">The number of periods to offset (positive or negative).</param>
        /// <returns>Returns the timeslice for a given timestamp and offset</returns>
        private long GetTimeSlice(long timestamp, int offset)
        {
            return (timestamp / Period) + (offset * Period);
        }

        /// <summary>
        /// Converts a <see cref="DateTime"/> to timestamp (based on UNIX EPOCH, see <see cref="EPOCH"/>).
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/> to calculate the timestamp from.</param>
        /// <returns>Returns the timestamp for the specified <see cref="DateTime"/>.</returns>
        private long DateTimeToTimestamp(DateTime value)
        {
            return (long)(value.ToUniversalTime() - EPOCH).TotalSeconds;
        }

        private DateTime GetTime()
        {
            return TimeProvider.GetTimeAsync().Result;
        }

        /// <summary>
        /// Provides a timing-attack safe method of comparing 2 strings.
        /// </summary>
        /// <param name="safe">The safe/trusted string to compare.</param>
        /// <param name="user">The unsafe/user provided string to compare.</param>
        /// <returns>Returns when two strings are equal, false otherwise.</returns>
        private static bool CodeEquals(string safe, string user)
        {
            // In general, it's not possible to prevent length leaks. So it's OK to leak the length. The important part
            // is that we don't leak information about the difference of the two strings.
            if (safe.Length == user.Length)
            {
                var result = 0;
                for (int i = 0; i < safe.Length; i++)
                    result |= safe[i] ^ user[i];
                return result == 0;
            }
            return false;
        }

        /// <summary>
        /// Generates a TOTP Uri with specified label and secret.
        /// </summary>
        /// <param name="label">The label for the TOTP Uri.</param>
        /// <param name="secret">The secret for the TOTP Uri.</param>
        /// <returns>Returns a TOTP Uri with specified label and secret.</returns>
        public string GetQrText(string label, string secret)
        {
            var x = "otpauth://totp/" + Uri.EscapeDataString(label)
                + "?secret=" + Uri.EscapeDataString(secret)
                + "&issuer=" + Uri.EscapeDataString(Issuer ?? string.Empty)
                + "&period=" + Period
                + "&algorithm=" + Uri.EscapeDataString(Enum.GetName(typeof(Algorithm), Algorithm).ToUpperInvariant())
                + "&digits=" + Digits;
            return x;
        }

        /// <summary>
        /// Provides a method for decoding a Base32 encoded string and exposes the Base32 "alphabet" for internal uses.
        /// </summary>
        internal static class Base32
        {
            public const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            private static readonly Regex _b32re = new Regex("[^" + Base32Alphabet + "]", RegexOptions.Compiled);
            private static readonly Dictionary<char, byte> _base32lookup = Base32Alphabet.Select((c, i) => new { c, i }).ToDictionary(v => v.c, v => (byte)v.i);

            public static byte[] Decode(string value)
            {
                // Have anything to decode?
                if (value == null)
                    throw new ArgumentNullException(nameof(value));

                // Remove padding
                value = value.TrimEnd('=');

                // Quick-exit if nothing to decode
                if (value == string.Empty)
                    return new byte[0];

                // Make sure string contains only chars from Base32 "alphabet"
                if (_b32re.IsMatch(value))
                    throw new ArgumentException("Invalid base32 string", nameof(value));

                // Decode Base32 value (not world's most efficient or beatiful code but it gets the job done.
                var bits = string.Concat(value.Select(c => Convert.ToString(_base32lookup[c], 2).PadLeft(5, '0')));
                return Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TwoFactorAuth.Net.Providers.Qr;
using TwoFactorAuth.Net.Providers.Rng;

namespace TwoFactorAuth.Net
{
    // Based on / inspired by: https://github.com/RobThree/TwoFactorAuth and https://github.com/PHPGangsta/GoogleAuthenticator
    // Algorithms, digits, period etc. explained: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    public class TwoFactorAuth
    {
        public string Issuer { get; private set; }
        public int Digits { get; private set; }
        public int Period { get; private set; }
        public Algorithm Algorithm { get; private set; }
        public IQrCodeProvider QrCodeProvider { get; private set; }
        public IRngProvider RngProvider { get; private set; }

        private readonly Encoding ENCODING = Encoding.ASCII;
        private readonly DateTime EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private const int DEFAULTDISCREPANCY = 1;
        private const int DEFAULTSECRETBITS = 80;
        private const int DEFAULTPERIOD = 30;
        private const int DEFAULTDIGITS = 6;
        private const int DEFAULTQRCODESIZE = 200;
        private const Algorithm DEFAULTALGORITHM = Algorithm.SHA1;

        public TwoFactorAuth()
            : this(null)
        { }

        public TwoFactorAuth(string issuer)
            : this(issuer, DEFAULTDIGITS)
        { }

        public TwoFactorAuth(string issuer, int digits)
            : this(issuer, digits, DEFAULTPERIOD)
        { }

        public TwoFactorAuth(string issuer, int digits, int period)
            : this(issuer, digits, period, DEFAULTALGORITHM)
        { }

        public TwoFactorAuth(string issuer, int digits, int period, Algorithm algorithm)
            : this(issuer, digits, period, algorithm, new GoogleQrCodeProvider())
        { }

        public TwoFactorAuth(string issuer, int digits, int period, Algorithm algorithm, IQrCodeProvider qrcodeprovider)
            : this(issuer, digits, period, algorithm, qrcodeprovider, new DefaultRngProvider())
        { }

        public TwoFactorAuth(string issuer, IQrCodeProvider qrcodeprovider)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, DEFAULTALGORITHM, qrcodeprovider, new DefaultRngProvider())
        { }

        public TwoFactorAuth(string issuer, IRngProvider rngprovider)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, DEFAULTALGORITHM, new GoogleQrCodeProvider(), rngprovider)
        { }

        public TwoFactorAuth(string issuer, IQrCodeProvider qrcodeprovider, IRngProvider rngprovider)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, DEFAULTALGORITHM, qrcodeprovider, rngprovider)
        { }

        public TwoFactorAuth(string issuer, Algorithm algorithm)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, algorithm, new GoogleQrCodeProvider(), new DefaultRngProvider())
        { }

        public TwoFactorAuth(string issuer, Algorithm algorithm, IQrCodeProvider qrcodeprovider)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, algorithm, qrcodeprovider, new DefaultRngProvider())
        { }

        public TwoFactorAuth(string issuer, Algorithm algorithm, IRngProvider rngprovider)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, algorithm, new GoogleQrCodeProvider(), rngprovider)
        { }

        public TwoFactorAuth(string issuer, Algorithm algorithm, IQrCodeProvider qrcodeprovider, IRngProvider rngprovider)
            : this(issuer, DEFAULTDIGITS, DEFAULTPERIOD, algorithm, qrcodeprovider, rngprovider)
        { }

        public TwoFactorAuth(string issuer, int digits, int period, Algorithm algorithm, IQrCodeProvider qrcodeprovider, IRngProvider rngprovider)
        {
            this.Issuer = issuer;

            if (digits <= 0)
                throw new ArgumentOutOfRangeException("digits");
            this.Digits = digits;

            if (period <= 0)
                throw new ArgumentOutOfRangeException("period");
            this.Period = period;

            if (!Enum.IsDefined(typeof(Algorithm), algorithm))
                throw new ArgumentOutOfRangeException("algorithm");
            this.Algorithm = algorithm;

            if (qrcodeprovider == null)
                throw new ArgumentNullException("qrcodeprovider");
            this.QrCodeProvider = qrcodeprovider;

            if (rngprovider == null)
                throw new ArgumentNullException("rngprovider");
            this.RngProvider = rngprovider;
        }

        public string CreateSecret()
        {
            return this.CreateSecret(DEFAULTSECRETBITS, CryptoSecureRequirement.RequireSecure);
        }

        public string CreateSecret(int bits)
        {
            return this.CreateSecret(bits, CryptoSecureRequirement.RequireSecure);
        }

        public string CreateSecret(int bits, CryptoSecureRequirement cryptoSecure)
        {
            if (cryptoSecure == CryptoSecureRequirement.RequireSecure && !this.RngProvider.IsCryptographicallySecure)
                throw new TwoFactorAuthException("RNG provider is not cryptographically secure");

            int bytes = (int)Math.Ceiling((double)bits / 5);    // We use 5 bits of each byte (since we have a
                                                                // 32-character 'alphabet' / BASE32)

            // Note that we DO NOT actually "base32 encode" the random bytes, we simply grab random letters from the
            // base32 alphabet which doesn't matter for a random secret.
            return string.Concat(this.RngProvider.GetRandomBytes(bytes).Select(v => _base32dict[v & 31]));
        }

        public string GetCode(string secret)
        {
            return this.GetCode(secret, DateTime.UtcNow);
        }

        public string GetCode(string secret, DateTime dateTime)
        {
            return this.GetCode(secret, this.DateTimeToTimestamp(dateTime));
        }

        public string GetCode(string secret, long timestamp)
        {
            using (var algo = KeyedHashAlgorithm.Create("HMAC" + Enum.GetName(typeof(Algorithm), this.Algorithm)))
            {

                algo.Key = Base32Decode(secret);
                var ts = BitConverter.GetBytes(this.GetTimeSlice(timestamp, 0));
                var hashhmac = algo.ComputeHash(new byte[] { 0, 0, 0, 0, ts[3], ts[2], ts[1], ts[0] });
                var offset = hashhmac[hashhmac.Length - 1] & 0x0F;
                return (((
                    hashhmac[offset + 0] << 24 |
                    hashhmac[offset + 1] << 16 |
                    hashhmac[offset + 2] << 8 |
                    hashhmac[offset + 3]
                ) & 0x7FFFFFFF) % (long)Math.Pow(10, this.Digits)).ToString().PadLeft(this.Digits, '0');
            }
        }

        private long GetTimeSlice(long timeslice, int offset)
        {
            return (timeslice / this.Period) + (offset * this.Period);
        }


        private long DateTimeToTimestamp(DateTime value)
        {
            return (long)(value.ToUniversalTime() - EPOCH).TotalSeconds;
        }

        public bool VerifyCode(string secret, string code)
        {
            return this.VerifyCode(secret, code, DEFAULTDISCREPANCY);
        }


        public bool VerifyCode(string secret, string code, int discrepancy)
        {
            return this.VerifyCode(secret, code, discrepancy, DateTime.UtcNow);
        }

        public bool VerifyCode(string secret, string code, int discrepancy, DateTime dateTime)
        {
            return this.VerifyCode(secret, code, discrepancy, this.DateTimeToTimestamp(dateTime));
        }

        public bool VerifyCode(string secret, string code, int discrepancy, long timestamp)
        {
            if (secret == null)
                throw new ArgumentNullException("secret");
            if (code == null)
                throw new ArgumentNullException("code");

            var result = false;

            // To keep safe from timing-attachs we iterate *all* possible codes even though we already may have
            // verified a code is correct.
            for (int i = -discrepancy; i <= discrepancy; i++)
                result |= CodeEquals(this.GetCode(secret, timestamp + (i * this.Period)), code);

            return result;
        }

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

        public string GetQrCodeImageAsDataUri(string label, string secret)
        {
            return GetQrCodeImageAsDataUri(label, secret, DEFAULTQRCODESIZE);
        }

        public string GetQrCodeImageAsDataUri(string label, string secret, int size)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException("size");

            return "data:"
                + this.QrCodeProvider.GetMimeType()
                + ";base64,"
                + Convert.ToBase64String(this.QrCodeProvider.GetQrCodeImage(this.GetQrText(label, secret), size));
        }

        private string GetQrText(string label, string secret)
        {
            var x = "otpauth://totp/" + Uri.EscapeDataString(label)
                + "?secret=" + Uri.EscapeDataString(secret)
                + "&issuer=" + Uri.EscapeDataString(this.Issuer)
                + "&period=" + this.Period
                + "&algorithm=" + Uri.EscapeDataString(Enum.GetName(typeof(Algorithm), this.Algorithm).ToUpperInvariant())
                + "&digits=" + this.Digits;
            return x;
        }

        #region base32
        private static string _base32dict = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
        private static readonly Regex _b32re = new Regex("[^" + _base32dict + "]", RegexOptions.Compiled);
        private static readonly Dictionary<char, byte> _base32lookup = _base32dict.Select((c, i) => new { c, i }).ToDictionary(v => v.c, v => (byte)v.i);

        //TODO: This should be internal/private; for now for unittesting against known vectors we'll leave it public...
        public static byte[] Base32Decode(string value)
        {
            if (value == null)
                throw new ArgumentNullException("value");

            if (_b32re.IsMatch(value))
                throw new ArgumentException("Invalid base32 string", "value");

            //TODO: Use a decent implementation instead of the ugly "to binary string to bytes" method
            var binstr = string.Concat(value.TrimEnd('=').Select(c => Convert.ToString(_base32lookup[c], 2).PadLeft(5, '0')));
            var result = new byte[binstr.Length / 8];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(binstr.Substring(i * 8, 8), 2);
            return result;
        }
        #endregion
    }
}

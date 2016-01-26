using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TwoFactorAuthNet.Providers.Qr;
using TwoFactorAuthNet.Providers.Rng;

namespace TwoFactorAuthNet.Tests
{
    [TestClass]
    public class TwoFactorAuthTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ConstructorThrowsOnInvalidDigits()
        {
            var target = new TwoFactorAuth(null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ConstructorThrowsOnInvalidPeriod()
        {
            var target = new TwoFactorAuth(null, 6, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ConstructorThrowsOnInvalidAlgorithm()
        {
            var target = new TwoFactorAuth(null, 6, 30, (Algorithm)999);
        }


        [TestMethod]
        public void GetCodeReturnsCorrectResults()
        {
            var target = new TwoFactorAuth();
            Assert.AreEqual("543160", target.GetCode("VMR466AB62ZBOKHE", 1426847216));
            Assert.AreEqual("538532", target.GetCode("VMR466AB62ZBOKHE", 0));
        }


        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void CreateSecretThrowsOnInsecureRNGProvider()
        {
            var rng = new TestRNGProvider();
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1, new TestQrProvider(), rng);
            target.CreateSecret();
        }

        [TestMethod]
        public void CreateSecretOverrideAllowInsecureDoesNotThrowOnInsecureRNG()
        {
            var rng = new TestRNGProvider(false);
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1, new TestQrProvider(), rng);
            var r = target.CreateSecret(80, CryptoSecureRequirement.AllowInsecure);
            Assert.AreEqual("ABCDEFGHIJKLMNOP", target.CreateSecret(80, CryptoSecureRequirement.AllowInsecure));
        }

        [TestMethod]
        public void CreateSecretOverrideAllowInsecureDoesNotThrowOnSecureRNG()
        {
            var rng = new TestRNGProvider(true);
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1, new TestQrProvider(), rng);
            var r = target.CreateSecret();
            Assert.AreEqual("ABCDEFGHIJKLMNOP", target.CreateSecret());
        }

        [TestMethod]
        public void CreateSecretGeneratesDesiredAmountOfEntropy()
        {
            var rng = new TestRNGProvider(true);
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1, new TestQrProvider(), rng);


            Assert.AreEqual("A", target.CreateSecret(5));
            Assert.AreEqual("AB", target.CreateSecret(6));
            Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZ", target.CreateSecret(128));
            Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", target.CreateSecret(160));
            Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", target.CreateSecret(320));
            Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567A", target.CreateSecret(321));
        }

        [TestMethod]
        public void VerifyCodeWorksCorrectly()
        {
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1);
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 1, 1426847190));
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 0, 1426847190 + 29));	    // Test discrepancy
            Assert.IsFalse(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 0, 1426847190 + 30));	// Test discrepancy
            Assert.IsFalse(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 0, 1426847190 - 1));	    // Test discrepancy
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 1, 1426847205 + 0));	    // Test discrepancy
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 1, 1426847205 + 35));	    // Test discrepancy
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 1, 1426847205 - 35));	    // Test discrepancy
            Assert.IsFalse(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 1, 1426847205 + 65));	// Test discrepancy
            Assert.IsFalse(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 1, 1426847205 - 65));	    // Test discrepancy
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 2, 1426847205 + 65));	    // Test discrepancy
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", 2, 1426847205 - 65));	    // Test discrepancy
        }

        [TestMethod]
        public void VerifyCodeAllowsNegativeDiscrepancy()
        {
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1);
            Assert.IsTrue(target.VerifyCode("VMR466AB62ZBOKHE", "543160", -2, 1426847205 - 65));	    // Test negative discrepancy
        }


        [TestMethod]
        public void VerifyTotpUriIsCorrect()
        {
            var qr = new TestQrProvider();
            var target = new TwoFactorAuth("Test&Issuer", 6, 30, Algorithm.SHA1, qr);

            var data = DecodeDataUri(target.GetQrCodeImageAsDataUri("Test&Label", "VMR466AB62ZBOKHE"));
            Assert.AreEqual("test/test", data["mimetype"]);
            Assert.AreEqual("base64", data["encoding"]);
            Assert.AreEqual("otpauth://totp/Test%26Label?secret=VMR466AB62ZBOKHE&issuer=Test%26Issuer&period=30&algorithm=SHA1&digits=6@200", data["data"]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void GetQrCodeImageAsDataUriThrowsOnInvalidSize()
        {
            var qr = new TestQrProvider();
            var target = new TwoFactorAuth(null, 6, 30, Algorithm.SHA1, qr);

            target.GetQrCodeImageAsDataUri("Test", "VMR466AB62ZBOKHE", 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GetCodeThrowsOnInvalidBase32String1()
        {
            var target = new TwoFactorAuth();

            target.GetCode("FOO1BAR8BAZ9"); // 1, 8 & 9 are invalid chars
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GetCodeThrowsOnInvalidBase32String2()
        {
            var target = new TwoFactorAuth(); 

            target.GetCode("mzxw6==="); // Lowercase
        }

        [TestMethod]
        public void KnownTestVectors_SHA1()
        {
            //Known test vectors for SHA1: https://tools.ietf.org/html/rfc6238#page-15
            var secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";    //== base32encode('12345678901234567890')
            var target = new TwoFactorAuth(null, 8, 30, Algorithm.SHA1);

            // Test specific timestamps
            Assert.AreEqual("94287082", target.GetCode(secret, 59));
            Assert.AreEqual("07081804", target.GetCode(secret, 1111111109));
            Assert.AreEqual("14050471", target.GetCode(secret, 1111111111));
            Assert.AreEqual("89005924", target.GetCode(secret, 1234567890));
            Assert.AreEqual("69279037", target.GetCode(secret, 2000000000));
            Assert.AreEqual("65353130", target.GetCode(secret, 20000000000));

            // Same values, this time as DateTime instead of timestamp
            Assert.AreEqual("94287082", target.GetCode(secret, new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc)));
            Assert.AreEqual("07081804", target.GetCode(secret, new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc)));
            Assert.AreEqual("14050471", target.GetCode(secret, new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc)));
            Assert.AreEqual("89005924", target.GetCode(secret, new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc)));
            Assert.AreEqual("69279037", target.GetCode(secret, new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc)));
            Assert.AreEqual("65353130", target.GetCode(secret, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));
        }

        [TestMethod]
        public void KnownTestVectors_SHA256()
        {
            //Known test vectors for SHA256: https://tools.ietf.org/html/rfc6238#page-15
            var secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";   //== base32encode('12345678901234567890123456789012')
            var target = new TwoFactorAuth(null, 8, 30, Algorithm.SHA256);

            // Test specific timestamps
            Assert.AreEqual("46119246", target.GetCode(secret, 59));
            Assert.AreEqual("68084774", target.GetCode(secret, 1111111109));
            Assert.AreEqual("67062674", target.GetCode(secret, 1111111111));
            Assert.AreEqual("91819424", target.GetCode(secret, 1234567890));
            Assert.AreEqual("90698825", target.GetCode(secret, 2000000000));
            Assert.AreEqual("77737706", target.GetCode(secret, 20000000000));

            // Same values, this time as DateTime instead of timestamp
            Assert.AreEqual("46119246", target.GetCode(secret, new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc)));
            Assert.AreEqual("68084774", target.GetCode(secret, new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc)));
            Assert.AreEqual("67062674", target.GetCode(secret, new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc)));
            Assert.AreEqual("91819424", target.GetCode(secret, new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc)));
            Assert.AreEqual("90698825", target.GetCode(secret, new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc)));
            Assert.AreEqual("77737706", target.GetCode(secret, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));
        }

        [TestMethod]
        public void KnownTestVectors_SHA512()
        {
            //Known test vectors for SHA512: https://tools.ietf.org/html/rfc6238#page-15
            var secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"; //== base32encode('1234567890123456789012345678901234567890123456789012345678901234')
            var target = new TwoFactorAuth(null, 8, 30, Algorithm.SHA512);

            // Test specific timestamps
            Assert.AreEqual("90693936", target.GetCode(secret, 59));
            Assert.AreEqual("25091201", target.GetCode(secret, 1111111109));
            Assert.AreEqual("99943326", target.GetCode(secret, 1111111111));
            Assert.AreEqual("93441116", target.GetCode(secret, 1234567890));
            Assert.AreEqual("38618901", target.GetCode(secret, 2000000000));
            Assert.AreEqual("47863826", target.GetCode(secret, 20000000000));

            // Same values, this time as DateTime instead of timestamp
            Assert.AreEqual("90693936", target.GetCode(secret, new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc)));
            Assert.AreEqual("25091201", target.GetCode(secret, new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc)));
            Assert.AreEqual("99943326", target.GetCode(secret, new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc)));
            Assert.AreEqual("93441116", target.GetCode(secret, new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc)));
            Assert.AreEqual("38618901", target.GetCode(secret, new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc)));
            Assert.AreEqual("47863826", target.GetCode(secret, new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));
        }


        private static Dictionary<string, string> DecodeDataUri(string dataUri)
        {
            var re = new Regex(@"data:(?<mimetype>[\w\.\-\/]+);(?<encoding>\w+),(?<data>.*)", RegexOptions.Compiled | RegexOptions.ExplicitCapture);
            var match = re.Match(dataUri);
            if (match.Success)
            {
                return new Dictionary<string, string>() { 
                    { "mimetype", match.Groups["mimetype"].Value },
                    { "encoding", match.Groups["encoding"].Value },
                    { "data", Encoding.ASCII.GetString(Convert.FromBase64String(match.Groups["data"].Value)) }
                };
            }
            return null;
        }

        [TestMethod]
        public void Base32DecodePaddedKnownVectors()
        {
            // We usually don't test internals (e.g. privates) but since we rely heavily on base32 decoding and don't
            // want to expose this method nor do we want to give people the possibility of implementing / providing
            // their own base32 decoding/decoder (as we do with Rng/QR providers for example) we simply test the
            // private Base32.Decode() method with some known testvectors **only** to ensure base32 decoding works
            // correctly following RFC's so there won't be any bugs hiding in there. We **could** 'fool' ourselves by
            // calling the public GetCode() method (which uses Base32.Decode() internally) and then make sure GetCode's
            // output (in digits) equals expected output since that would mean the Base32.Decode() works as expected
            // but that **could** hide some subtle bug(s) in decoding the base32 string.

            // "In general, you don't want to break any encapsulation for the sake of testing (or as Mom used to say,
            // "don't expose your privates!"). Most of the time, you should be able to test a class by exercising its
            // public methods."
            //                                                     Dave Thomas and Andy Hunt -- "Pragmatic Unit Testing

            var target = typeof(TwoFactorAuth).Assembly.GetType("TwoFactorAuthNet.TwoFactorAuth+Base32");
            var method = target.GetMethod("Decode");
            
            // Test vectors from: https://tools.ietf.org/html/rfc4648#page-12
            Assert.AreEqual("", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "" })));
            Assert.AreEqual("f", Encoding.ASCII.GetString((byte[])method.Invoke(target, new [] { "MY======" })));
            Assert.AreEqual("fo", Encoding.ASCII.GetString((byte[])method.Invoke(target, new [] { "MZXQ====" })));
            Assert.AreEqual("foo", Encoding.ASCII.GetString((byte[])method.Invoke(target, new [] { "MZXW6===" })));
            Assert.AreEqual("foob", Encoding.ASCII.GetString((byte[])method.Invoke(target, new [] { "MZXW6YQ=" })));
            Assert.AreEqual("fooba", Encoding.ASCII.GetString((byte[])method.Invoke(target, new [] { "MZXW6YTB" })));
            Assert.AreEqual("foobar", Encoding.ASCII.GetString((byte[])method.Invoke(target, new [] { "MZXW6YTBOI======" })));
        }

        [TestMethod]
        public void Base32DecodeUnpaddedKnownVectors()
        {
            // See Base32DecodePaddedKnownVectors() for the rationale behind testing the private Base32/Decode()
            // method. This test ensures that strings without the padding-char ('=') are also decoded correctly.
            // https://tools.ietf.org/html/rfc4648#page-4: 
            //   "In some circumstances, the use of padding ("=") in base-encoded data is not required or used."

            var target = typeof(TwoFactorAuth).Assembly.GetType("TwoFactorAuthNet.TwoFactorAuth+Base32");
            var method = target.GetMethod("Decode");

            // Test vectors from: https://tools.ietf.org/html/rfc4648#page-12
            Assert.AreEqual("", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "" })));
            Assert.AreEqual("f", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "MY" })));
            Assert.AreEqual("fo", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "MZXQ" })));
            Assert.AreEqual("foo", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "MZXW6" })));
            Assert.AreEqual("foob", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "MZXW6YQ" })));
            Assert.AreEqual("fooba", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "MZXW6YTB" })));
            Assert.AreEqual("foobar", Encoding.ASCII.GetString((byte[])method.Invoke(target, new[] { "MZXW6YTBOI" })));
        }
    }


    internal class TestRNGProvider : IRngProvider
    {
        private bool _issecure;

        public TestRNGProvider()
            : this(false) { }

        public TestRNGProvider(bool isSecure)
        {
            _issecure = isSecure;
        }

        public byte[] GetRandomBytes(int bytes)
        {
            return Enumerable.Range(0, bytes).Select(b => (byte)b).ToArray();
        }

        public bool IsCryptographicallySecure
        {
            get { return _issecure; }
        }
    }

    internal class TestQrProvider : IQrCodeProvider
    {
        public byte[] GetQrCodeImage(string text, int size)
        {
            return Encoding.ASCII.GetBytes(string.Format("{0}@{1}", text, size));
        }

        public string GetMimeType()
        {
            return "test/test";
        }
    }
}

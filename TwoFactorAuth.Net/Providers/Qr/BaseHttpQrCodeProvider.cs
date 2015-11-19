using System;
using System.Drawing;
using System.Net;

namespace TwoFactorAuth.Net.Providers.Qr
{
    public abstract class BaseHttpQrCodeProvider
    {
        //TODO: Use VerifySSL
        //TODO: Be able to set proxy
        //TODO: Get name/version dynamically for useragent instead of hardcoded?

        protected SslPolicy SslPolicy { get; set; }

        public BaseHttpQrCodeProvider(SslPolicy sslPolicy)
        {
            if (!Enum.IsDefined(typeof(SslPolicy), sslPolicy))
                throw new ArgumentOutOfRangeException("sslPolicy");
            this.SslPolicy = sslPolicy;
        }

        protected virtual byte[] DownloadData(Uri address)
        {
            using (var wc = this.GetWebClient())
            {
                return wc.DownloadData(address);
            }
        }

        protected virtual WebClient GetWebClient()
        {
            return this.GetWebClient(TimeSpan.FromSeconds(10));
        }

        protected virtual WebClient GetWebClient(TimeSpan timeOut)
        {
            var wc = new ExtendedWebClient(timeOut);
            wc.Headers.Add(HttpRequestHeader.UserAgent, "TwoFactorAuth");
            return wc;
        }

        protected static string Color2Hex(Color value)
        {
            return value.R.ToString("X2") + value.G.ToString("X2") + value.B.ToString("X2");
        }

        private class ExtendedWebClient : WebClient
        {
            private TimeSpan _timeout;

            public ExtendedWebClient(TimeSpan timeOut)
            {
                this._timeout = timeOut;
            }

            protected override WebRequest GetWebRequest(Uri address)
            {
                var wr = base.GetWebRequest(address);
                wr.Timeout = (int)_timeout.TotalMilliseconds;
                return wr;
            }
        }
    }
}

using System;
using System.Drawing;
using System.Net;
using System.Net.Cache;

namespace TwoFactorAuth.Net.Providers.Qr
{
    public abstract class BaseHttpQrCodeProvider
    {
        //TODO: Use VerifySSL
        

        protected SslPolicy SslPolicy { get; set; }

        /// <summary>
        /// Gets/sets the base URI to use when downloading files and relative paths are specified.
        /// </summary>
        public Uri BaseUri { get; private set; }
        /// <summary>
        /// Gets/sets the application's cache policy for any resources obtained by this instance.
        /// </summary>
        public RequestCachePolicy CachePolicy { get; set; }
        /// <summary>
        /// Gets/sets the network credentials that are sent to the host and used to authenticate the request.
        /// </summary>
        public ICredentials Credentials { get; set; }
        /// <summary>
        /// Gets/sets the proxy used by this instance.
        /// </summary>
        public IWebProxy Proxy { get; set; }
        /// <summary>
        /// Gets/sets the default timeout.
        /// </summary>
        public TimeSpan TimeOut { get; set; }
        /// <summary>
        /// Gets the useragent string used to identify when downloading QR codes.
        /// </summary>
        public static readonly string USERAGENT = string.Format("{0} v{1}", typeof(BaseHttpQrCodeProvider).Assembly.GetName().Name, typeof(BaseHttpQrCodeProvider).Assembly.GetName().Version.ToString());
        /// <summary>
        /// Gets the default timeout for downloading QR codes.
        /// </summary>
        public static readonly TimeSpan DEFAULTTIMEOUT = TimeSpan.FromSeconds(10);

        protected BaseHttpQrCodeProvider(Uri baseUri, SslPolicy sslPolicy)
        {
            if (baseUri == null)
                throw new ArgumentNullException("baseUri");
            this.BaseUri = baseUri;

            if (!Enum.IsDefined(typeof(SslPolicy), sslPolicy))
                throw new ArgumentOutOfRangeException("sslPolicy");
            this.SslPolicy = sslPolicy;
            
            this.TimeOut = DEFAULTTIMEOUT;
        }

        protected virtual byte[] DownloadData(Uri address)
        {
            using (var wc = this.GetWebClient())
                return wc.DownloadData(address);
        }

        protected virtual WebClient GetWebClient()
        {
            var wc = new ExtendedWebClient(this.TimeOut);
            wc.CachePolicy = this.CachePolicy;
            wc.Credentials = this.Credentials;
            wc.Proxy = this.Proxy;
            wc.Headers.Add(HttpRequestHeader.UserAgent, USERAGENT);
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

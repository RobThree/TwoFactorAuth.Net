using System;
using System.Globalization;
using System.Net;
using System.Net.Cache;
using System.Net.Http;
using System.Threading.Tasks;

namespace TwoFactorAuthNet.Providers.Time
{
    /// <summary>
    /// Provides time information from a webserver by doing a HEAD request and extracting the Date HTTP response header.
    /// </summary>
    public class HttpTimeProvider : ITimeProvider
    {
        /// <summary>
        /// The default Uri used to 'query'.
        /// </summary>
        public const string DEFAULTURI = "https://google.com";
        
        /// <summary>
        /// Gets the Uri to be queried.
        /// </summary>
        public Uri Uri { get; private set; }

        /// <summary>
        /// Gets/sets the <see cref="RequestCachePolicy"/> used when performing requests.
        /// </summary>
        public RequestCachePolicy CachePolicy { get; set; } = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore);

        /// <summary>
        /// Gets/sets the <see cref="IWebProxy"/> to use when performing requests.
        /// </summary>
        public IWebProxy Proxy { get; set; }


        /// <summary>
        /// Initializes a new instance of a <see cref="HttpTimeProvider"/>.
        /// </summary>
        /// <param name="uri">The uri to query; defaults to <see cref="DEFAULTURI"/>.</param>
        public HttpTimeProvider(string uri = DEFAULTURI)
            : this(new Uri(uri)) { }

        /// <summary>
        /// Initializes a new instance of a <see cref="HttpTimeProvider"/>.
        /// </summary>
        /// <param name="uri"></param>
        public HttpTimeProvider(Uri uri)
        {
            this.Uri = uri ?? new Uri(DEFAULTURI);
        }

        /// <summary>
        /// Gets the time from the webserver by performing a HEAD request on the specified <see cref="Uri"/>.
        /// </summary>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public async Task<DateTime> GetTimeAsync()
        {
            try
            {
                using (var c = new HttpClient(new WebRequestHandler()
                {
                    CachePolicy = this.CachePolicy,
                    Proxy = this.Proxy,
                    UseProxy = this.Proxy != null,
                    AllowAutoRedirect = false
                }))
                {
                    using (var req = new HttpRequestMessage(HttpMethod.Head, this.Uri))
                    {
                        var response = await c.SendAsync(req);

                        if (response.Headers.Date.HasValue)
                            return response.Headers.Date.Value.UtcDateTime;
                    }
                }
            }
            catch { }

            throw new TimeProviderException($"Unable to retrieve time data from {this.Uri}");
        }
    }
}

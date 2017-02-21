using System;
using System.Net;
using System.Net.Cache;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace TwoFactorAuthNet.Providers.Time
{
    /// <summary>
    /// Provides time information retrieved from the public API of convert-unix-time.com.
    /// </summary>
    public class ConvertUnixTimeDotComTimeProvider : ITimeProvider
    {
        private static readonly Uri BASEURI = new Uri("http://www.convert-unix-time.com/api?timestamp=now");
        private static readonly DateTime EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        // We *EITHER* "quick'n'dirty" regex the timestamp OR introduce a dependency on a JSON library / System.Web.Script.Serialization.JavaScriptSerializer 
        private Regex jsontimestamp = new Regex(@"\""timestamp\""\s*:\s*(\d+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        /// <summary>
        /// Gets/sets the <see cref="RequestCachePolicy"/> used when performing requests.
        /// </summary>
        public RequestCachePolicy CachePolicy { get; set; } = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore);

        /// <summary>
        /// Gets/sets the <see cref="IWebProxy"/> to use when performing requests.
        /// </summary>
        public IWebProxy Proxy { get; set; }

        /// <summary>
        /// Gets the time from the public API of convert-unix-time.com.
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
                    UseProxy = this.Proxy!=null,
                    AllowAutoRedirect = false
                }))
                {
                    var m = jsontimestamp.Match(await c.GetStringAsync(BASEURI).ConfigureAwait(false));
                    return EPOCH.AddSeconds(int.Parse(m.Groups[1].Value));
                }
            }
            catch { }
            throw new TimeProviderException($"Unable to retrieve time data from {BASEURI}");
        }
    }
}

using System;
using System.Drawing;
using System.Net;
using System.Net.Cache;
using System.Net.Security;

namespace TwoFactorAuthNet.Providers.Qr;

/// <summary>
/// Provides a base implementation for QR code providers.
/// </summary>
public abstract class BaseHttpQrCodeProvider
{
    /// <summary>
    /// Gets a callback function to validate the server certificate.
    /// </summary>
    protected RemoteCertificateValidationCallback? RemoteCertificateValidationCallback { get; private set; }

    /// <summary>
    /// Gets the base URI to use when downloading files.
    /// </summary>
    public Uri BaseUri { get; private set; }

    /// <summary>
    /// Gets/sets the application's cache policy for any resources obtained by this instance.
    /// </summary>
    public RequestCachePolicy? CachePolicy { get; set; }

    /// <summary>
    /// Gets/sets the network credentials that are sent to the host and used to authenticate the request.
    /// </summary>
    public ICredentials? Credentials { get; set; }

    /// <summary>
    /// Gets/sets the proxy used by this instance.
    /// </summary>
    public IWebProxy? Proxy { get; set; }

    /// <summary>
    /// Gets/sets the default timeout.
    /// </summary>
    public TimeSpan TimeOut { get; set; }

    /// <summary>
    /// Gets/sets whether an SSL connection is required.
    /// </summary>
    public bool RequireSsl { get; set; }

    /// <summary>
    /// Gets the useragent string used to identify when downloading QR codes.
    /// </summary>
    public static readonly string USERAGENT = $"{typeof(BaseHttpQrCodeProvider).Assembly.GetName().Name} v{typeof(BaseHttpQrCodeProvider).Assembly.GetName().Version}";

    /// <summary>
    /// Gets the default timeout for downloading QR codes.
    /// </summary>
    public static readonly TimeSpan DEFAULTTIMEOUT = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Initializes a new instance of a <see cref="BaseHttpQrCodeProvider"/>.
    /// </summary>
    /// <param name="baseUri">The base Uri for the QR code provider.</param>
    /// <param name="remoteCertificateValidationCallback">
    /// The <see cref="RemoteCertificateValidationCallback"/> to be used by the QR code provider.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="baseUri"/> is null.</exception>
    protected BaseHttpQrCodeProvider(Uri baseUri, RemoteCertificateValidationCallback? remoteCertificateValidationCallback)
    {
        BaseUri = baseUri ?? throw new ArgumentNullException(nameof(baseUri));

        RemoteCertificateValidationCallback = remoteCertificateValidationCallback;
        TimeOut = DEFAULTTIMEOUT;
    }

    /// <summary>
    /// Downloads the resource with the specified <see cref="Uri"/> as a <see cref="byte"/> array.
    /// </summary>
    /// <param name="address">The URI represented by the <see cref="Uri"/> object, from which to download data.</param>
    /// <returns>A <see cref="byte"/> array containing the downloaded resource.</returns>
    protected virtual byte[] DownloadData(Uri address)
    {
        if (address == null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (RequireSsl && string.Compare(address.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) != 0)
        {
            throw new ProtocolViolationException("An SSL connection is required");
        }

        using var wc = GetWebClient();
        return wc.DownloadData(address);
    }

    /// <summary>
    /// Creates and returns a <see cref="WebClient"/> initialized with all default / desired properties already set.
    /// </summary>
    /// <returns>Returns an initialized <see cref="WebClient"/>.</returns>
    protected virtual WebClient GetWebClient()
    {
        var wc = new ExtendedWebClient(TimeOut, RemoteCertificateValidationCallback)
        {
            CachePolicy = CachePolicy,
            Credentials = Credentials,
            Proxy = Proxy
        };
        wc.Headers.Add(HttpRequestHeader.UserAgent, USERAGENT);
        return wc;
    }

    /// <summary>
    /// Returns the hexadecimal value for an RGB (<see cref="Color"/>) value.
    /// </summary>
    /// <param name="value">The <see cref="Color"/> to convert.</param>
    /// <returns>Returns the hexadecimal value for an RGB (<see cref="Color"/>) value.</returns>
    protected static string Color2Hex(Color value) => $"{value.R:X2}{value.G:X2}{value:B:X2}";

    /// <summary>
    /// Extended webclient where a timeout can be specified/set.
    /// </summary>
    private class ExtendedWebClient : WebClient
    {
        private TimeSpan _timeout;
        private readonly RemoteCertificateValidationCallback? _remotecertificatevalidationcallback;

        public ExtendedWebClient(TimeSpan timeOut, RemoteCertificateValidationCallback? remoteCertificateValidationCallback)
        {
            _timeout = timeOut;
            _remotecertificatevalidationcallback = remoteCertificateValidationCallback;
        }

        protected override WebRequest GetWebRequest(Uri address)
        {
            var wr = (HttpWebRequest)base.GetWebRequest(address);
            wr.Timeout = (int)_timeout.TotalMilliseconds;
            wr.ServerCertificateValidationCallback = _remotecertificatevalidationcallback;
            return wr;
        }
    }
}

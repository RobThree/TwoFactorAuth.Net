using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TwoFactorAuthNet.Providers.Time;

/// <summary>
/// Provides time information from an NTP server by doing an NTP request and parsing the result.
/// </summary>
public class NTPTimeProvider : ITimeProvider
{
    /// <summary>
    /// The default host used to query.
    /// </summary>
    public static string DefaultHost => "pool.ntp.org";

    /// <summary>
    /// The default port used to query.
    /// </summary>
    public static int DefaultPort => 123;

    /// <summary>
    /// The default send- and receive timeout used when querying NTP host.
    /// </summary>
    public static TimeSpan DefaultTimeout => TimeSpan.FromSeconds(3);

    /// <summary>
    /// Gets the host to be queried.
    /// </summary>
    public string Host { get; private set; }

    /// <summary>
    /// Gets the port used to query.
    /// </summary>
    public int Port { get; private set; }

    /// <summary>
    /// Gets the default send timeout.
    /// </summary>
    public TimeSpan SendTimeout { get; private set; }

    /// <summary>
    /// Gets the default receive timeout.
    /// </summary>
    public TimeSpan ReceiveTimeout { get; private set; }

    private static readonly Random _rng = new();

    /// <summary>
    /// Initializes a new instance of a <see cref="NTPTimeProvider"/>.
    /// </summary>
    /// <param name="host">The host to query; defaults to <see cref="DefaultHost"/>.</param>
    /// <param name="port">The port to query; defaults to <see cref="DefaultPort"/>.</param>
    /// <param name="sendTimeout">The send timeout when querying NTP host.</param>
    /// <param name="receiveTimeout">The receive timeout when querying NTP host.</param>
    public NTPTimeProvider(string? host = null, int port = 123, TimeSpan? sendTimeout = null, TimeSpan? receiveTimeout = null)
    {
        Host = host ?? DefaultHost;

        if (port is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        Port = port;

        sendTimeout ??= DefaultTimeout;
        if (sendTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(sendTimeout));
        }

        SendTimeout = sendTimeout.Value;

        receiveTimeout ??= DefaultTimeout; ;
        if (receiveTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(receiveTimeout));
        }

        ReceiveTimeout = receiveTimeout.Value;
    }

    /// <summary>
    /// Gets the time from an NTP server by performing an NTP request on the specified <see cref="Host"/>.
    /// </summary>
    /// <returns>The task object representing the asynchronous operation.</returns>
    public Task<DateTime> GetTimeAsync()
    {
        // Slightly modified version of https://stackoverflow.com/a/20157068/215042

        try
        {
            var ntpData = new byte[48];
            ntpData[0] = 0x1B; //LeapIndicator = 0 (no warning), VersionNum = 3 (IPv4 only), Mode = 3 (Client Mode)

            var addresses = Dns.GetHostEntry(Host).AddressList;
            if (addresses.Length > 0)
            {
                // Pick random IP from returned addresses
                var rhost = _rng.Next(0, addresses.Length);
                using var socket = new Socket(addresses[rhost].AddressFamily, SocketType.Dgram, ProtocolType.Udp)
                {
                    SendTimeout = (int)SendTimeout.TotalMilliseconds,
                    ReceiveTimeout = (int)ReceiveTimeout.TotalMilliseconds
                };
                socket.Connect(new IPEndPoint(addresses[rhost], Port));
                socket.Send(ntpData);
                socket.Receive(ntpData);
                socket.Close();

                var intPart = ((ulong)ntpData[40] << 24) | ((ulong)ntpData[41] << 16) | ((ulong)ntpData[42] << 8) | ntpData[43];
                var fractPart = ((ulong)ntpData[44] << 24) | ((ulong)ntpData[45] << 16) | ((ulong)ntpData[46] << 8) | ntpData[47];

                var milliseconds = (intPart * 1000) + (fractPart * 1000 / 0x100000000L);
                return Task.FromResult(new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(milliseconds));
            }
        }
        catch { }

        throw new TimeProviderException($"Unable to retrieve time data from {Host}");
    }
}

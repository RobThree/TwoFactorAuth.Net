using System;
using System.Threading.Tasks;

namespace TwoFactorAuthNet.Providers.Time;

/// <summary>
/// Provides the interface for time providers.
/// </summary>
public interface ITimeProvider
{
    /// <summary>
    /// Gets the time from the time provider.
    /// </summary>
    /// <returns>The task object representing the asynchronous operation.</returns>
    Task<DateTime> GetTimeAsync();
}

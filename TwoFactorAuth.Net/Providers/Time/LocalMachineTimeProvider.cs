using System;
using System.Threading.Tasks;

namespace TwoFactorAuthNet.Providers.Time
{
    /// <summary>
    /// Provides time information from the local machine.
    /// </summary>
    public class LocalMachineTimeProvider : ITimeProvider
    {
        /// <summary>
        /// Gets the time from the local machine.
        /// </summary>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public Task<DateTime> GetTimeAsync()
        {
            return Task.FromResult(DateTime.UtcNow);
        }
    }
}

using System;

namespace TwoFactorAuthNet.Providers.Time
{
    /// <summary>
    /// Represents the exception that is thrown when a problem occurs during time retrieval of an <see cref="ITimeProvider"/>.
    /// </summary>
    public class TimeProviderException : Exception
    {
        /// <summary>
        /// Initializes a new instance of a <see cref="TimeProviderException"/>.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public TimeProviderException(string message)
            : base(message) { }
    }
}
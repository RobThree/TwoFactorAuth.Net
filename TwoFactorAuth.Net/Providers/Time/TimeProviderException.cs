using System;
using System.Runtime.Serialization;

namespace TwoFactorAuthNet.Providers.Time
{
    /// <summary>
    /// Represents the exception that is thrown when a problem occurs during time retrieval of an <see cref="ITimeProvider"/>.
    /// </summary>
    [Serializable]
    public class TimeProviderException : Exception
    {

        /// <summary>
        /// Initializes a new instance of a <see cref="TimeProviderException"/>.
        /// </summary>
        public TimeProviderException()
        : base() { }

        /// <summary>
        /// Initializes a new instance of a <see cref="TimeProviderException"/>.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public TimeProviderException(string message)
            : base(message) { }

        /// <summary>
        /// Initializes a new instance of a <see cref="TimeProviderException"/>.
        /// </summary>
        /// <param name="message">The message to be given for the exception.</param>
        /// <param name="innerException">The inner exception.</param>
        public TimeProviderException(string message, Exception innerException)
            : base(message, innerException) { }

        /// <summary>
        /// Initializes a new, empty instance of the <see cref="TimeProviderException" /> class that is serializable using the
        /// specified <see cref="SerializationInfo" /> and <see cref="StreamingContext" /> objects.
        /// </summary>
        /// <param name="serializationInfo">The information required to serialize the <see cref="TimeProviderException" /> object.</param>
        /// <param name="streamingContext">The source and destination of the serialized stream associated with the <see cref="TimeProviderException" /> object.</param>
        protected TimeProviderException(System.Runtime.Serialization.SerializationInfo serializationInfo, System.Runtime.Serialization.StreamingContext streamingContext)
        {
            throw new NotImplementedException();
        }
    }
}
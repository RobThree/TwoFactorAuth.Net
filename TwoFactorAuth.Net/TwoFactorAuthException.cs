using System;

namespace TwoFactorAuth.Net
{
    public class TwoFactorAuthException : Exception
    {
        public TwoFactorAuthException(string message)
            : base(message) { }

    }
}

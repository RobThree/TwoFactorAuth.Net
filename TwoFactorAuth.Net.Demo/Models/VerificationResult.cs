using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TwoFactorAuth.Net.Demo.Models
{
    public class VerificationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
    }
}
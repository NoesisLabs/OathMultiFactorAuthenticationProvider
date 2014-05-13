using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OtpSharp
{
    /// <summary>
    /// An generic ntp exception
    /// </summary>
    [Serializable]
    public class NtpException : Exception
    {
        /// <summary>
        /// NtpException with a message
        /// </summary>
        /// <param name="message">Message</param>
        public NtpException(string message)
            :base(message)
        {
            
        }
    }
}

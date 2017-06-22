using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace http.signature.Exceptions
{
    public class InvalidAlgorithmException : Exception 
    {
        public InvalidAlgorithmException() { }

        public InvalidAlgorithmException(string message) : base(message) { }

        public InvalidAlgorithmException(string message, Exception inner) : base(message, inner) { }

    }
}

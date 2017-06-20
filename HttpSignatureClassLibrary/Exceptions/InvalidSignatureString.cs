using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace http.signature.Exceptions
{
    public class InvalidSignatureString : Exception
    {

        public InvalidSignatureString() { }

        public InvalidSignatureString(string message) : base(message)  { }

        public InvalidSignatureString(string message, Exception inner) : base(message, inner) { }

    }
}

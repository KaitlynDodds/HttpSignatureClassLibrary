using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace http.signature.Exceptions
{
    public class InvalidAuthorizationHeader : Exception
    {
        public InvalidAuthorizationHeader() { }

        public InvalidAuthorizationHeader(string message) : base(message) { }

        public InvalidAuthorizationHeader(string message, Exception inner) : base(message, inner) { }
        
    }
}

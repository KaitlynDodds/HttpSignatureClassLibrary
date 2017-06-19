using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace http.signature
{
    public class Algorithm
    {

        // List of all available algorithms
        public static readonly Algorithm HMAC_SHA256 = new Algorithm("hmac-sha256");

        // associate Algorithm common name w/ Algorithm instance 
        private static readonly Dictionary<string, Algorithm> aliases = new Dictionary<string, Algorithm>
        {
            { HMAC_SHA256.CommonName, HMAC_SHA256 }
        };

        public string CommonName { get; private set; }


        public static Algorithm Get(string name)
        {
            // given a name, fetch back the correct algorithm (or throw error)
            Algorithm algorithm = Algorithm.aliases[name];

            if (algorithm == null)
            {
                // FIXME: kzd -> throw, algorithm not found error
            }
            return algorithm;
        }

        public Algorithm(string commonName)
        {
            CommonName = commonName;
        }

    }
}

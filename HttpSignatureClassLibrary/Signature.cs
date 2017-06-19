using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace http.signature
{
    public class Signature
    {
        /*
        REQUIRED The `keyId` field is an opaque string that the server can
        use to look up the component they need to validate the signature.  It
        could be an SSH key fingerprint, a URL to machine-readable key data,
        an LDAP DN, etc.  Management of keys and assignment of `keyId` is out
        of scope for this document. 
        */
        public string KeyId { get; private set; }

        /*
        REQUIRED The `algorithm` parameter is used to specify the digital
        signature algorithm to use when generating the signature.  Valid
        values for this parameter can be found in the Signature Algorithms
        registry located at http://www.iana.org/assignments/signature-
        algorithms and MUST NOT be marked "deprecated".
        */
        public Algorithm Algorithm { get; private set; }

        /*
         REQUIRED The `signature` parameter is a base 64 encoded digital
        signature, as described in RFC 4648 [RFC4648], Section 4 [4].  The
        client uses the `algorithm` and `headers` signature parameters to
        form a canonicalized `signing string`.  This `signing string` is then
        signed with the key associated with `keyId` and the algorithm
        corresponding to `algorithm`.  The `signature` parameter is then set
        to the base 64 encoding of the signature.
         */
        public string EncodedSignature { get; set; }

        public Request Request { get; private set; }    // represents HTTP request that will be used to generate the signature 
        
        public Signature(string keyId, string algorithm, Request request)
        {
            SetupSignature(keyId, GetAlgorithm(algorithm), request);
        }

        public Signature(string keyid, Algorithm algorithm, Request request)
        {
            SetupSignature(keyid, algorithm, request);

        }

        private void SetupSignature(string keyid, Algorithm algorithm, Request request)
        {

            // keyid cannot be null or empty
            if (String.IsNullOrEmpty(keyid.Trim())) throw new ArgumentException("KeyId cannot be null or empty");
            KeyId = keyid.Trim().ToLower();

            // Algorithm cannot be null
            Algorithm = algorithm ?? throw new ArgumentNullException("Algorithm cannot be null");

            // Request cannot be null
            Request = request ?? throw new ArgumentNullException("Request cannot not be null");

        }

        private static Algorithm GetAlgorithm(string algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException("Algorithm can't be null");
            return Algorithm.Get(algorithm);
        }

        private string JoinHeaders()
        {
            string headerString = "";
            foreach (var header in Request.OrderedHeaders)
            {
                headerString += String.Format("{0} ", header.Trim().ToLower());
            }

            // Trim to clean up trailing space
            return headerString.Trim();
        }

        /*
         Returns fully formatted Authorization header
         **Should be used as the value of the Authorization header for the request 
        */
        public override string ToString()
        {
            return
                "keyId=\"" + KeyId + "\"," +
                "algorithm=\"" + Algorithm.CommonName + "\"," +
                "headers=\"" + "(request-target) "
                + JoinHeaders() + "\"," +
                "signature=\"" + EncodedSignature + "\"";
        }

        public static bool IsValidSignature(string scheme, string parameter)
        {
            /*
             Resembles:
             	Signature "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"KcLSABBj/m3v2DhxiCKJmzYJvnx74tDO1SaURD8Dr8XpugN5wpy8iBVJtpkHUIp4qBYpzx2QvD16t8X0BUMiKc53Age+baQFWwb2iYYJzvuUL+krrl/Q7H6fPBADBsHqEZ7IE8rR0Ys3lb7J5A6VB9J/4yVTRiBcxTypW/mpr5w=\""
            */

            // scheme must be 'Signature'
            if (!scheme.Equals("Signature")) return false;

            // correct paramter values must be included, valid
            if (!IsValidParamter(parameter)) return false;

            return true;
        }

        private static bool IsValidParamter(string parameter)
        {
            // TODO: REFACTOR!! DRY coding (copied code in Parse.ParseAuthenticationHeader) 

            // MUST include keyId, algorithm, headers, signature 
            string[] VALID_KEYS = new string[] { "keyId", "algorithm", "headers", "signature" };
            // MUST include required headers 
            string[] REQUIRED_HEADERS = new string[] { "(request-target)", "date", "digest" };

            // get all key="value" pairs from parameter
            string[] pairs = parameter.Split(',');
            foreach (var pair in pairs)
            {
                // extract key
                string key = Regex.Match(pair, @"\b[a-zA-Z]+\b").ToString();
                if (!VALID_KEYS.Contains(key)) return false;  // not a valid key, not a valid signature 

                // extract value 
                string[] split = pair.Split('"');  // splits on quotes, second value in list will be the value we want 
                string value = split[1];  // should return the unquoted, unaltered value passed into the header for this key value pair 

                // check that key 'headers' contains required header values 
                if (key.Equals("headers"))
                {
                    string[] hValues = value.Split(' ');
                    foreach (var REQ_HEADER in REQUIRED_HEADERS)
                    {
                        if (!hValues.Contains(REQ_HEADER)) return false; 
                    }
                }
            }
            
            return true;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
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

        public static Signature FromHttpRequest(HttpRequestMessage httpRequest)
        {
            string keyId = "";          // keyId value passed w/ Signature Authorization
            string algorithm = "";      // algorithm value passed w/ Signature Authorization
            string signature = "";      // original hashed signature value that was passed with Authorization header 

            // headers that were used to hash Signature, should use these headers to test hash 
            List<string> orderedHeaders = new List<string>(); 
            
            // store headers and header values that should be used to create Request object 
            Dictionary<string, List<string>> headersToUse = new Dictionary<string, List<string>>();


            string method = httpRequest.Method.ToString();
            string path = httpRequest.RequestUri.ToString();

            if (httpRequest.Headers.Authorization == null || Parser.IsValidAuthenticationHeader(httpRequest.Headers.Authorization))
            {
                throw new ArgumentNullException("Invalid HttpRequestMessage, HttpRequestMessage should include valid Authorization header.");
            }

            try
            {
                // ParseAuthorizationHeader returns dic with Authorization header values that should be used to create new Signature 
                Dictionary<string, List<string>> signatureValues = Parser.ParseSignatureString(httpRequest.Headers.Authorization.Parameter);

                keyId = signatureValues["keyId"][0];
                algorithm = signatureValues["algorithm"][0];
                orderedHeaders = signatureValues["headers"];
                signature = signatureValues["signature"][0];

                
                // loop through httprequestmessage headers
                foreach (var httpHeader in httpRequest.Headers)
                {
                    // if orderedHeaders (headers used to hash original signature) contains that httpheader
                    if (orderedHeaders.Contains(httpHeader.Key.ToLower()))
                    {
                        // add that httpheader and values to headersToUse 
                        headersToUse.Add(httpHeader.Key, new List<string>(httpHeader.Value));
                    }
                }
            }
            catch (Exception ex)
            {
                // something went wrong while parseing values, unable to create Signature 
                throw new Exception("Invalid Signature Creation", ex);
            }

            // return new Signature object
            return new Signature(keyId, algorithm, new Request(method, path, headersToUse, orderedHeaders), signature);
        }

        public static Signature FromHttpRequest(HttpRequestMessage httpRequest, string keyId, string algorithm)
        {
            string method = httpRequest.Method.ToString();
            string path = httpRequest.RequestUri.ToString();

            // headers that should be used to create hashed Signature string (must be listed in order they are used to hash the Signature) 
            List<string> orderedHeaders = new List<string>();
            // headers and values that should be used to create hashed Signature string (dictionary does not guarantee order) 
            Dictionary<string, List<string>> headersToUse = new Dictionary<string, List<string>>();

            try
            {
                // loop through each header in httprequestmessage
                foreach (var httpHeader in httpRequest.Headers)
                {
                    // add header to orderedHeaders
                    orderedHeaders.Add(httpHeader.Key);
                    // add header and values
                    headersToUse.Add(httpHeader.Key, new List<string>(httpHeader.Value));
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Invalid Signature Creation", ex);
            }

            // return new Signature 
            return new Signature(keyId, algorithm, new Request(method, path, headersToUse, orderedHeaders));
        }

        public Signature(string keyId, string algorithm, Request request, string sig)
        {
            // if Signature string already exists 
            EncodedSignature = sig;

            SetupSignature(keyId, GetAlgorithm(algorithm), request);
        }

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
         **Should be used as the parameter value of the Authorization header for the request 
        */
        public override string ToString()
        {
            return
                "keyId=\"" + KeyId + "\"," +
                "algorithm=\"" + Algorithm.CommonName + "\"," +
                "headers=\"" + JoinHeaders() + "\"," +
                "signature=\"" + EncodedSignature + "\"";
        }
        
        public static bool IsValidSignatureString(string parameter)
        {
            // correct paramter values must be included, valid
            Dictionary<string, List<string>> parsedSignatureValues = Parser.ParseSignatureString(parameter);
            return IsValidSignatureString(parsedSignatureValues);
        }

        /*
        Checks that the expected/required values have been included and correctly parsed from
        the Signature string 
        */
        public static bool IsValidSignatureString(Dictionary<string, List<string>> signatureValues)
        {
            /*
             Resembles:
             	Signature "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"date digest\",signature=\"KcLSABBj/m3v2DhxiCKJmzYJvnx74tDO1SaURD8Dr8XpugN5wpy8iBVJtpkHUIp4qBYpzx2QvD16t8X0BUMiKc53Age+baQFWwb2iYYJzvuUL+krrl/Q7H6fPBADBsHqEZ7IE8rR0Ys3lb7J5A6VB9J/4yVTRiBcxTypW/mpr5w=\""
            */
            
            if (signatureValues["keyId"] == null || String.IsNullOrEmpty(signatureValues["keyId"][0].Trim()))
            {
                // invalid keyId
                return false;
            }
            if (signatureValues["algorithm"] == null || String.IsNullOrEmpty(signatureValues["algorithm"][0].Trim()) || GetAlgorithm(signatureValues["algorithm"][0]) == null)
            {
                // invalid algorithm 
                return false;
            }
            if (signatureValues["headers"] == null || signatureValues["headers"].Count == 0)
            {
                // invalid headers
                return false;
            }
            if (signatureValues["signature"] == null || String.IsNullOrEmpty(signatureValues["signature"][0]))
            {
                // invalid signature value
                return false;
            }

            return true;

        }

    }
}

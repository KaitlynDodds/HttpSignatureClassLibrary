using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace http.signature
{
    public class Signer
    {
        private Signature Signature;

        private string[] REQUIRED_HEADERS = { "date", "host" };

        public Signer(Signature signature)
        {
            Signature = signature ?? throw new ArgumentNullException("Signature cannot be null");
        }

        public bool Verify(string encodedSignature)
        {
            // encodedSignature is signature that was received in HTTP Authorization header

            // run sign on signature, compare newly generated signature with encodedSignature
            string newEncodedSignature = Sign().EncodedSignature;

            // if they match, the data was not tampered with, if they are different, data integrity breached 
            if (String.Equals(newEncodedSignature, encodedSignature))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public Signature Sign()
        {
            // minimum data to sign 
            // (request-header) date host 
            if (PassMinimumDataCheck(Signature.Request.Headers))
            {
                // Step 1: Signature String Construction
                string signatureString = generateSignatureString();

                // Step 2: generate digital string 
                string digitalString = generateDigitalString(Signature.Algorithm, Signature.KeyId, signatureString);    // digital signature takes for of Base64(HMAC-SHA256(signatureString))

                // assign digitalString to signature field of Signature
                Signature.EncodedSignature = digitalString;
            }
            else
            {
                //throw new invalid request 
                // send back 401 w/ Authentication header, auth-scheme, auth-param values 
            }

            // signature has now been signed
            return Signature;
        }

        private bool PassMinimumDataCheck(Dictionary<string, List<string>> headers)
        {
            foreach (var reqHeader in REQUIRED_HEADERS)
            {
                if (!headers.ContainsKey(reqHeader)) return false;
            }
            return true;
        }

        private string generateDigitalString(Algorithm algorithm, string keyId, string signatureString)
        {
            string digitalString;

            // determine which algorithm you should be using 
            switch (algorithm.CommonName)
            {
                case "hmac-sha256":
                    // test w/ HMAC-SHA256 algorithm 
                    digitalString = SignDigitalStringHMAC256(keyId, signatureString);
                    break;
                default:
                    digitalString = null;
                    break;
            }

            // string is now hashed and encoded
            return digitalString;
        }

        private string SignDigitalStringHMAC256(string keyId, string signatureString)
        {

            // FIXME: For now, hardcode key that should be used to hash HMAC algorithm 
            string HMAC_KEY = "Feg20ShPuW9rdxV12e20nkoKNXI=";

            // new hmac instance to work with 
            HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(HMAC_KEY));

            // need byte value of signatureString
            var signatureStringBytes = Encoding.UTF8.GetBytes(signatureString);
            // compute hash of signatureString 
            var hashValue = hmac.ComputeHash(signatureStringBytes);

            // algorithm expects base64 encoded string 
            return Convert.ToBase64String(hashValue);
        }

        private string generateSignatureString()
        {
            /*
             Response should resemble:
             (request-target): get /foo\n
             host: example.org\n
             date: ***\n
             digest: ***\n
             content-length: 18
             */

            string signatureString = "";
            // add request target
            signatureString += String.Format("(request-target): {0} {1}\n", Signature.Request.Method.ToLower(), Signature.Request.Path.ToLower());
            // add each header and value in the order they appear in the HTTP request 
            foreach (string header in Signature.Request.OrderedHeaders)
            {
                // headers must be add in value they appear in the request
                signatureString += String.Format("{0}: ", header);
                if (header.Equals("(request-target)"))
                {
                    break;
                }
                if (Signature.Request.Headers[header].Count > 1)
                {
                    foreach (string value in Signature.Request.Headers[header])
                    {
                        signatureString += String.Format("{0}, ", value);
                    }
                }
                else
                {
                    signatureString += String.Format("{0}\n", Signature.Request.Headers[header][0]);
                }
            }

            return signatureString.Trim();  // need to remove trailing '\n'
        }

        /************ Helper Methods ************/

        private Dictionary<string, List<string>> Normalize(Dictionary<string, List<string>> _headers)
        {
            Dictionary<string, List<string>> normalizedHeaders = new Dictionary<string, List<string>>();
            foreach (var header in _headers.Keys)
            {
                // must be all lowercased
                string normHeader = NormalizeString(header);
                normalizedHeaders.Add(normHeader, _headers[header]);
            }
            return normalizedHeaders;
        }

        private string NormalizeString(string value)
        {
            // FIXME: what does it mean to normalize?
            if (String.IsNullOrEmpty(value.Trim())) throw new ArgumentException("String value cannot be null or empty.");
            return value.ToLower();
        }

    }
}

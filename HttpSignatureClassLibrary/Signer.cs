using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace http.signature
{
    public class Signer
    {
        private Signature Signature;

        public Signer(Signature signature)
        {
            Signature = signature ?? throw new ArgumentNullException("Signature cannot be null");
        }

        /*
         * Should be run on the server side
         * 
         * Checks that the hashed value of Signature matches the unverifiedSignature (a hashed value)
         * 
         * returns true if hashed values match
         * return false if hashed values do not match 
         */
        public bool Verify(string unverifiedSignature)
        {
            // run sign to generate newly Signed signature 
            Sign();

            if (String.Equals(Signature.EncodedSignature, unverifiedSignature))
            {
                // if they match, the data was not tampered with
                return true;
            }
            else
            {
                // if they are different, data integrity breached
                return false;
            }
        }

        /*
         * Use to Sign the Signature instance 
         * 
         * uses Signature data to generate signature string, which is then
         * hashed using the hashing algorithm specified by the Signature,
         * hashed values is base64 encoded and assigned to the Signature
         * instances' EncodedSignature property 
         * 
         */
        public void Sign()
        {
            // Step 1: Signature String Construction
            string signatureString = generateSignatureString();

            // Step 2: generate digital string 
            string digitalString = generateDigitalString(signatureString); 

            // assign digitalString to signature field of Signature
            Signature.EncodedSignature = digitalString;
           
        }

        /*
         * Determines which algorithm to use to sign the signature string
         * 
         * uses algorithm to perform signing (base64 encoded hash value)
         * 
         * returns digitalstring that holds base64 encoded hash of signature string 
         */
        private string generateDigitalString(string signatureString)
        {
            string digitalString;

            // determine which algorithm you should be using 
            switch (Signature.Algorithm.CommonName)
            {
                case "hmac-sha256":
                    // only available option at the moment 
                    digitalString = SignDigitalStringHMAC256(signatureString);
                    break;
                default:
                    digitalString = null;
                    break;
            }

            // string is now hashed and encoded
            return digitalString;
        }

        /*
         * Does actual encryption of signature string using the keyId and algorithm
         * specified in the Signature instance 
         * 
         * Base64(HMAC-SHA256(signatureString))
         * 
         * returns base64 encoded value of hashed signature string (using HMAC-SHA256 hashing algorithm) 
         */
        private string SignDigitalStringHMAC256(string signatureString)
        {
            // FIXME: For now, hardcode key that should be used to hash HMAC algorithm 
            /* string keyId = GoGetKeyToUseBasedOnKeyId(Signature.KeyId) */
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

        /*
         * Formats Signature string in preparation for hashing the Signature
         * returns formatted list of headers and values 
         * 
         * header: value\nheader: value\header: value
         * 
         */
        private string generateSignatureString()
        {
            string signatureString = "";
            // add each header and value in the order they appear in the HTTP request 
            foreach (string header in Signature.Request.OrderedHeaders)
            {
                // headers must be add in value they appear in the request
                signatureString += String.Format("{0}: ", header);
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
            if (String.IsNullOrEmpty(value.Trim())) throw new ArgumentException("String value cannot be null or empty.");
            return value.ToLower();
        }

    }
}

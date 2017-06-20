using http.signature.Exceptions;
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
    public static class Parser
    {

        /*
        Given a AuthenticationHeaderValue
        Assesses validity of Authentication header
        Assesses validity of Signature 
        returns Dictionary with Signature values
        */
        public static void CheckValidAuthenticationHeader(AuthenticationHeaderValue authentication)
        {
            // authentication Scheme must be 'Signature'
            if (!authentication.Scheme.Equals("Signature"))
            {
                throw new InvalidAuthorizationHeader("Authorization header missing 'Signature' scheme.");
            }

            Signature.CheckIsValidSignatureString(authentication.Parameter);
        }

        /*
         * Signature String Resembles: "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"date digest\",signature=\"KcLSABBj/m3v2DhxiCKJmzYJvnx74tDO1SaURD8Dr8XpugN5wpy8iBVJtpkHUIp4qBYpzx2QvD16t8X0BUMiKc53Age+baQFWwb2iYYJzvuUL+krrl/Q7H6fPBADBsHqEZ7IE8rR0Ys3lb7J5A6VB9J/4yVTRiBcxTypW/mpr5w=\""
         * 
         * Must include keyId, algorithm, headers, signature keys 
         * Each key must have at least one value (headers should have at least the required headers)
         * 
         * Returns dictionary containing broken down signature string
         * 4 keys, one for keyId, algorithm, headers, signature each 
         * 
         */
        public static Dictionary<string, List<string>> ParseSignatureString(string parameter)
        {
            // valid Signature MUST include keyId, algorithm, headers, signature 
            string[] VALID_KEYS = new string[] { "keyId", "algorithm", "headers", "signature" };
            // valid Signature MUST include required headers 
            string[] REQUIRED_HEADERS = new string[] { "date", "digest" };
            
            Dictionary<string, List<string>> signatureValues = new Dictionary<string, List<string>>();
            
            // get all key="value" pairs from parameter
            string[] pairs = parameter.Split(',');  // splits on ',' returns "keyId=\"testvalue\" "algorithm=\"rsa-sha256\" etc. 
            foreach (var pair in pairs)
            {
                // extracts key from key-value pair in string (e.g. keyId, algorithm, signature, headers)
                string key = Regex.Match(pair, @"\b[a-zA-Z]+\b").ToString();
                // check that the key is valid 
                if (!VALID_KEYS.Contains(key)) throw new InvalidSignatureString("Signature contains invalid Key: " + key);    // not a valid key, not a valid signature 

                // extract value from key-value pair 
                string[] split = pair.Split('"');  // splits on quotes, second value in list will be the value we want 
                string value = split[1].Trim();  // should return the unquoted, unaltered value passed into the header for this key value pair 

                // 'header' key must contain minium required headers 
                if (key.Equals("headers"))
                {
                    string[] hValues = value.Split(' ');  // split on space
                    foreach (var REQ_HEADER in REQUIRED_HEADERS)
                    {
                        // check that each required header is included in 'headers'
                        if (!hValues.Contains(REQ_HEADER)) throw new InvalidSignatureString("Signature does not contain required header: " + REQ_HEADER);
                    }
                    // add all 'headers' values to dictionary 
                    signatureValues.Add(key, new List<string>(hValues));
                }
                else
                {
                    // add key-value pair to dictionary (each key except 'header' should only contain one value)
                    signatureValues.Add(key, new List<string> { value });
                }
            }

            // only want to return signature string we know is valid, otherwise throw error 
            Signature.CheckIsValidSignatureString(signatureValues);

            return signatureValues;

        }

    }
}

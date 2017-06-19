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

        public static Request ParseRequestFromHttpRequestMessage(HttpRequestMessage httpMessage)
        {
            string method = httpMessage.Method.ToString();

            string path = httpMessage.RequestUri.ToString();

            Dictionary<string, List<string>> parsedAuthorizationHeader = Parser.ParseAuthorizationHeader(httpMessage.Headers.Authorization);
            List<string> authHeaders = parsedAuthorizationHeader["headers"];  // gets headers from signature "headers" list - new request should only contain these headers 

            Dictionary<string, List<string>> headers = new Dictionary<string, List<string>>();

            // get headers
            HttpRequestHeaders requestHeaders = httpMessage.Headers;
            foreach (var header in requestHeaders)
            {
                if (authHeaders.Contains(header.Key.ToLower()))
                {
                    List<string> values = new List<string>(httpMessage.Headers.GetValues(header.Key));
                    headers.Add(header.Key, values);
                }
            }

            return new Request(method, path, headers, authHeaders);
        }

        public static Dictionary<string, List<string>> ParseAuthorizationHeader(AuthenticationHeaderValue authentication)
        {

            if (!authentication.Scheme.Equals("Signature"))
            {
                throw new ArgumentException("Invalid Authentication Header");  // FIXME: could be better error message
            }

            return ParseSignatureString(authentication.Parameter);
            
        }

        public static Dictionary<string, List<string>> ParseSignatureString(string parameter)
        {
            Dictionary<string, List<string>> signatureValues = new Dictionary<string, List<string>>();

            // MUST include keyId, algorithm, headers, signature 
            string[] VALID_KEYS = new string[] { "keyId", "algorithm", "headers", "signature" };
            // MUST include required headers 
            string[] REQUIRED_HEADERS = new string[] { "date", "digest" };

            // get all key="value" pairs from parameter
            string[] pairs = parameter.Split(',');
            foreach (var pair in pairs)
            {
                // extract key
                string key = Regex.Match(pair, @"\b[a-zA-Z]+\b").ToString();
                if (!VALID_KEYS.Contains(key)) throw new ArgumentException("Invalid Authentication Header");  // not a valid key, not a valid signature 

                // extract value 
                string[] split = pair.Split('"');  // splits on quotes, second value in list will be the value we want 
                string value = split[1];  // should return the unquoted, unaltered value passed into the header for this key value pair 

                // check that key 'headers' contains required header values 
                if (key.Equals("headers"))
                {
                    string[] hValues = value.Split(' ');
                    foreach (var REQ_HEADER in REQUIRED_HEADERS)
                    {
                        if (!hValues.Contains(REQ_HEADER)) throw new ArgumentException("Invalid Authentication Header");
                    }
                    signatureValues.Add(key, new List<string>(hValues));
                }
                else
                {
                    signatureValues.Add(key, new List<string> { value });
                }
            }
            
            return signatureValues;
        }

    }
}

using http.signature;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            mock();
        }

        public static void mock()
        {
            HttpRequestMessage request = ClientSide();

            /********************************************************************************************************/
            /*                                        client sends request                                          */
            /********************************************************************************************************/

            Serverside(request);

        }

        private static void Serverside(HttpRequestMessage req)
        {
            /********************************************************************************************************/
            /*                                        server receives request                                       */
            /********************************************************************************************************/

            // Step 1) Check that HTTPRequest Message contains Authorization header 
            if (req.Headers.Authorization == null || !Signature.IsValidSignature(req.Headers.Authorization.Scheme, req.Headers.Authorization.Parameter))
            {
                // send 401 Unauthorized if Request does not contain necessary headers + info
                // specify which headers are expected in WW-Authenticate header 
                //return Send401Response("Authorization Attempt Failed, Invalid Signature");
                Console.WriteLine("Authorization Attempt Failed, Invalid Signature");
            }

            // Step 2) Verify Signature 

            // a) Parse HttpResponseMessage to generate a Request object 
            Request request = Parser.ParseRequestFromHttpRequestMessage(req);

            // b) Parse Authorization header 
            Dictionary<string, List<string>> parsedAuthenticationHeaders = Parser.ParseAuthorizationHeader(req.Headers.Authorization);
            // keyId
            string keyId = parsedAuthenticationHeaders["keyId"][0];
            // algorithm
            string algorithm = parsedAuthenticationHeaders["algorithm"][0];
            // Signature (encoded value) 
            string requestSignature = parsedAuthenticationHeaders["signature"][0];

            // c) Create new Signature object with keyId, algorithm and Request object
            Signature signature = new Signature(keyId, algorithm, request);

            // d) Create new Signer object with Signature object
            Signer signer = new Signer(signature);

            // e) Call signer.Verify() given the encoded signature you received in the original HTTP request 
            if (signer.Verify(requestSignature))
            {
                // if true, signatures match, send back 200 OK
                //return req.CreateResponse(HttpStatusCode.OK, "Authorization Attempt Successful");
                Console.WriteLine("Authorization Attempt Successful");
            }
            else
            {
                // if false, signatures did not match, send back error (401?)
                //return Send401Response("Authorization Attempt Failed, Signature Verification Failed");
                Console.WriteLine("Authorization Attempt Failed, Signature Verification Failed");
            }

        }

        public static HttpRequestMessage ClientSide()
        {
            /********************************************************************************************************/
            /*                                        client generates request                                      */
            /********************************************************************************************************/
            string keyId = "hmac-key-1";
            string algorithm = "hmac-sha256";
            string address = "http://localhost:7071/api/HttpTriggerCSharp";
            HttpClient client = new HttpClient();
            HttpRequestMessage httprequest = new HttpRequestMessage()
            {
                RequestUri = new Uri(address),
                Method = HttpMethod.Get
            };

            // add signature to Authorization header
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            client.DefaultRequestHeaders.Date = DateTime.Today;
            client.DefaultRequestHeaders.Add("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
            client.DefaultRequestHeaders.Host = "localhost:7071";

            Request request = new Request(httprequest, client);

            Signature signature = new Signature(keyId, algorithm, request);

            Signer signer = new Signer(signature);

            signer.Sign();

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Signature", signature.ToString());

            Console.WriteLine("Signed Signature:\n");
            Console.WriteLine(signature.ToString());

            return httprequest;
        }
    }
}

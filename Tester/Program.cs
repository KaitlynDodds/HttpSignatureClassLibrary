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
            if (req.Headers.Authorization == null || Parser.IsValidAuthenticationHeader(req.Headers.Authorization))
            {
                // send 401 Unauthorized if Request does not contain necessary headers + info
                // specify which headers are expected in WW-Authenticate header 
                Console.WriteLine("Authorization Attempt Failed, Invalid Signature");
            }

            // Step 2) Verify Signature 


            // c) Create new Signature object with keyId, algorithm and Request object
            Signature signature = Signature.FromHttpRequest(req);
            string oldSig = signature.EncodedSignature;

            // d) Create new Signer object with Signature object
            Signer signer = new Signer(signature);

            // e) Call signer.Verify() given the encoded signature you received in the original HTTP request 
            if (signer.Verify(oldSig))
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
            HttpRequestMessage httprequest = new HttpRequestMessage()
            {
                RequestUri = new Uri(address),
                Method = HttpMethod.Get
            };

            // add signature to Authorization header
            httprequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httprequest.Headers.Date = DateTime.Today;
            httprequest.Headers.Add("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");

            Signature signature = Signature.FromHttpRequest(httprequest, keyId, algorithm);

            Signer signer = new Signer(signature);

            signer.Sign();

            httprequest.Headers.Authorization = new AuthenticationHeaderValue("Signature", signature.ToString());

            Console.WriteLine("Signed Signature:\n");
            Console.WriteLine(signature.ToString());

            return httprequest;
        }
    }
}

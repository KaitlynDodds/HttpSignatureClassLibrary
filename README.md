Http Signature Library and Function

Basic Structure of Process:
1) A client application wishes to connect to api-A
    a) the client creates an http request 
    b) the client decides which keyId and algorithm they are going to use to verify the request 
    c) the client uses the HttpSignature library to generate a signature hash value
    d) the client adds an Authorization header to the request and provides the signature hash 
    e) the client sends the request to api-A 

2) api-A is hosted on API Management 

3) API Management has a policy in place that checks all inbound traffic to api-A

    a) The policy receives the request intended for api-A
    b) the policy redirects the request to the verify-function 
    c) the verify-function receives the request and checks the validity of the request
       by parsing the Authentication header, and creating an http signature hash of
       the request
    d) if the http signature hash (that the verify-function creates) matches the hash
       value that was sent in the Authorization header of the request, the request
       will be verified

4) The API Management policy waits x seconds for a response from the verify-function

5) When the response is received, the policy checks for a json value that indicates
   if they request was verified by the verify-function or not

   if the request was verified:
        the Api Management policy allows the request to continue to api-A
   else
        the Api Management policy sends back a 401 response to the client application
        indicating that the request was not verified 


How to Generate an Http Signature - Client Application

The HttpSignature library was written with the expectation that you will be using the System.Net.Http.HttpClient suite of classes. Therefore, it will be much easier to create an HttpSignature if you use an HttpRequestMessage and HttpClient to generate and send
requests. However, this is not the only way to generate an http signature. It is possible to do so through other means, however it 
is not recommend. 

When generating your request, you must include at least a Date header and a Digest header. The Date header should be formatted as 'Tue, 07 Jun 2014 20:51:35 GMT'. These headers should be added to your HttpRequestMessage before it is used to generate a signature. 

The client application will need to take four very important steps before it is ready to send its http request. 

**Assumes you're working with an HttpRequestMessage

1) Create a new 'Signature' instance with the static call, FromHttpRequest. Provide your HttpRequestMessage object and the keyId and Algorithm you plan to use to use to hash the signature. 
  **Keep in mind that the KeyId needs to mean something to the 'server' or 'verifier' agent, ideally it should point to a secret shared key. 
  
 2) Create a new 'Signer' instance with the newly created signature object. 
 
 3) Call the static method, Sign(), on your Signer object. 
 
 4) Add an Authorization header to your HttpRequestMessage. The scheme of the header should be 'Signature'. The parameter should be the return value of yourSignatureObject.ToString()  

You should now be able to send your request


The Verification Process - Server Side

The HttpSignature library was written with the expectation that you will be using the System.Net.Http.HttpClient suite of classes. The verification process assumes that you are receiving http requests as HttpRequestMessages. 

The purpose of the verification process is to assert the integrity of the data send in the http request. The http request should include an Authorization header with a 'Signature' scheme and a parameter value that resembles this:

keyId="rsa-key-1",algorithm="rsa-sha256",headers="(request-target) host date digest content-length",signature="npbiWEI562rJYX80tHJhChTtMM+F5ncvR6nLSncrb34=" 

There are several key value pairs listed in this string, each has a very important purpose to the validation of the Authorization header. 

The key-id tells the server/verifying agent which secret key they should use to hash the http request that it has just received. 

The algorithm indicates which hashing algorithm the client used to hash the request before they sent it. 

The headers list lists each of the request headers that were included in the hashing of the request, in the order that they were used. 

The signature holds the base64 encoded, hashed value of the original http request that the client generated. 

The server/verifying agent will repeat the process of hashing the http request that it received and will generate a base64 encoded, hashed value based on the information provided in this Authorization header parameter. The newly hashed string will then be compared to the signature value that was passed in the Authorization parameter. If the two match, you know that the http request was not tampered with. If they don't match up, something was altered during the transport of the http request and that request cannot be trusted. 

In the event that the http request is unable to be verified, the server/verifying agent should respond with a 401 Unauthorized response.


How to Verify a Request

The HttpSignature library was written with the expectation that you will be using the System.Net.Http.HttpClient suite of classes. The verification process assumes that you are receiving http requests as HttpRequestMessages. 

There are four steps to the verification process:

1) Use the HttpRequestMessage object to create a 'Signature' instance using the static function FromHttpRequest()

2) Store in a string variable the 'EncodedSignature' property from your new 'Signature' object. You will need this later.

3) Create a new 'Signer' instance with your 'Signature' object. 

4) Call Verify() on your 'Signer' object, with the string 'EncodedSignature' variable you saved from the original 'Signature' object 

If the call to Verify returns true, the two hashed signature matched and the request can be verified. 
If the call to Verify returns false, the two hashed signatures did not match, so send back a 401.




# **Http Signature Library**  


#### **Signing Http Signatures**
This library is intended to be used as a means of authenticating the sender of an HTTP request, as well as verifying it's integrity. 

The library is written in C# and is intended to be used in conjuction with the `System.Net.Http` suite of classes.

For more information on the practice and process of [Signing Http Messages](https://datatracker.ietf.org/doc/draft-cavage-http-signatures/)... 

#### **How to Sign an Http Signature - Client Application**

When generating your request, you must include at least a **Date** header and a **Digest** header. The **Date** header should be formatted as *'Tue, 07 Jun 2014 20:51:35 GMT'*. These headers should be added to your `HttpRequestMessage` before it is used to generate a signature. 

The client application will need to take four steps before it is ready to send its http request. 

1. Create a new `Signature` instance with the static call, `FromHttpRequest`. Provide your `HttpRequestMessage` object and the keyId and Algorithm you plan to use to use to hash the signature. 
    *Keep in mind that the KeyId needs to mean something to the 'server' or 'verifier' agent, ideally it should point to a secret shared key.*

    `Signature signature = Signature.FromHttpRequest(request, keyId, alorithm);`
  
2. Create a new `Signer` instance with the newly created signature object. 
 
    `Signer signer = new Signer(signature);`

3. Call the static method, `Sign()`, on your Signer object. 

    `signer.Sign();`
 
4. Add an Authorization header to your `HttpRequestMessage`. The scheme of the header should be 'Signature'. The parameter should be the `ToString()` value of your signature.

    `new AuthenticationHeaderValue("Signature", signature.ToString());`


**You should now be able to send your request**


### **The Verification Process - Server Side**
The purpose of the verification process is to assert the integrity of the data send in the http request. The http request should include an Authorization header with a 'Signature' scheme and a parameter value that resembles this:

> keyId="rsa-key-1",algorithm="rsa-sha256",headers="(request-target) host date digest  content-length",signature="npbiWEI562rJYX80tHJhChTtMM+F5ncvR6nLSncrb34=" 

There are several key value pairs listed in this string, each is required in the Authorization paramter string. 

The *key-id* tells the server/verifying agent which secret key they should use to hash the http request that it has just received. 

The *algorithm* indicates which hashing algorithm the client used to hash the request before they sent it. 

The *headers* list lists each of the request headers that were included in the hashing of the request, in the order that they were used. 

The *signature* holds the base64 encoded, hashed value of the original http request that the client generated. 

The server/verifying agent will repeat the process of hashing the http request that it received and will generate a base64 encoded, hashed value based on the information provided in this Authorization header parameter. The newly hashed string will then be compared to the signature value that was passed in the Authorization parameter. If the two match, you know that the http request was not tampered with. If they don't match up, something was altered during the transport of the http request and that request cannot be trusted. 

In the event that the http request is unable to be verified, the server/verifying agent should respond with a 401 Unauthorized response.

#### **How to Verify a Request**

The HttpSignature library was written with the expectation that you will be using the System.Net.Http.HttpClient suite of classes. The verification process assumes that you are receiving http requests as HttpRequestMessages. 

There are four steps to the verification process:

1. Use the HttpRequestMessage object to create a 'Signature' instance using the static function FromHttpRequest()

    `Signature signature = Signature.FromHttpRequest(request);`

2. Store in a string variable the 'EncodedSignature' property from your new 'Signature' object. You will need this later.

    `string encodedSignature = signature.EncodedSignature();`

3. Create a new 'Signer' instance with your 'Signature' object. 

    `Signer signer = new Signer(signature);`

4. Call Verify() on your 'Signer' object, with the string 'EncodedSignature' variable you saved from the original 'Signature' object 

    `signer.Verify(encodedSignature);`

If the call to Verify returns **true**, the two hashed signature matched and the request can be verified. If the call to Verify returns **false**, the two hashed signatures did not match, so send back a 401.

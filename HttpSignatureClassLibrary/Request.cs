using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace http.signature
{
    public class Request
    {
        public string Method { get; private set; }  // POST, GET, PUT, DELETE

        public string Path { get; private set; }    // /foo/bar?param=value

        public Dictionary<string, List<string>> Headers { get; private set; }   // Content-Length: 18, Host: example.org 

        public List<string> OrderedHeaders { get; private set; }                // stores the same headers as Headers, but in the order they were listed in the HTTP Request 

        public Request(string method, string path, Dictionary<string, List<string>> headers, List<string> orderedHeaders)
        {
            SetUpRequest(method, path, headers, orderedHeaders);   
        }

        public Request(HttpRequestMessage httprequest, HttpClient client)
        {
            string method = httprequest.Method.Method;

            string path = httprequest.RequestUri.ToString();

            Dictionary<string, List<string>> headers = new Dictionary<string, List<string>>();
            List<string> orderedHeaders = new List<string>();
            foreach (var header in client.DefaultRequestHeaders)
            {
                headers.Add(header.Key, new List<string>(header.Value));
                orderedHeaders.Add(header.Key);
            }

            SetUpRequest(method, path, headers, orderedHeaders);
        }

        private void SetUpRequest(string method, string path, Dictionary<string, List<string>> headers, List<string> orderedHeaders)
        {
            if (String.IsNullOrEmpty(method.Trim())) throw new ArgumentException("Method cannot be null or empty");
            Method = NormalizeString(method);

            if (String.IsNullOrEmpty(path.Trim())) throw new ArgumentException("Path cannot be null or empty");
            Path = NormalizeString(path);

            // headers cannot be null
            Headers = headers ?? throw new ArgumentNullException("Headers cannot be null");
            Headers = NormalizeRequestHeaders();

            // orderedHeaders cannot be null
            OrderedHeaders = orderedHeaders ?? throw new ArgumentNullException("OrderedHeaders cannot be null");
            OrderedHeaders = NormalizeOrderedHeaders();

            // make sure OrderedHeaders and Headers contain the same list of headers
            if (CompareOrderedToNonOrdered()) throw new ArgumentException("Headers and OrderedHeaders do not contain the same header values");
        }

        private bool CompareOrderedToNonOrdered()
        {
            for (int i = 0; i < OrderedHeaders.Count; ++i)
            {
                if (Headers.ContainsKey(OrderedHeaders[i])) return false;
            }
            return true;
        }

        private List<string> NormalizeOrderedHeaders()
        {
            List<string> normalizedOrderedHeaders = new List<string>();
            for (int i = 0; i < OrderedHeaders.Count; ++i)
            {
                normalizedOrderedHeaders.Insert(i, NormalizeString(OrderedHeaders[i]));
            }
            return normalizedOrderedHeaders;
        }

        private Dictionary<string, List<string>> NormalizeRequestHeaders()
        {
            Dictionary<string, List<string>> normalizedRequestHeaders = new Dictionary<string, List<string>>();
            foreach (var header in Headers.Keys)
            {
                // header should be lowercase, trimmed
                string normHeader = header.Trim().ToLower();

                // values should be trimmed 
                List<string> values = new List<string>();
                foreach (var value in Headers[header])
                {
                    values.Add(value.Trim());
                }

                // add normalized values into new Headers dic
                normalizedRequestHeaders.Add(normHeader, values);
            }
            return normalizedRequestHeaders;
        }

        private string NormalizeString(string value)
        {
            return value.Trim().ToLower();
        }

    }
}

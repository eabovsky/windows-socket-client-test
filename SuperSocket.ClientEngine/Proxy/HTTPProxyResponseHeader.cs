using System;
using System.IO;
using System.Diagnostics;
using System.Collections;


namespace SuperSocket.ClientEngine.Proxy
{
    public class HTTPProxyResponseHeader
    {

        private const string m_ResponsePrefix = "HTTP/1.1";
        private const char m_Space = ' ';

        public int StatusCode;
        public Hashtable SupportedSecurityPackages = new Hashtable();
        public string SecurityPackage;
        public bool AuthNeeded = false;
        public bool HasChallangeToken = false;
        public string ChallangeToken;
        public bool ReconnectNeeded = true;

        public string ErrorMessage = null;
        public bool HasError = false;
        public string Via;

        public void logHeader(string responseString)
        {
            Debug.WriteLine("\r\n[***RESPONSE HEADER START***]");
            Debug.WriteLine(responseString);
            Debug.WriteLine("[***RESPONSE HEADER END***]\r\n");
        }

        public HTTPProxyResponseHeader(string responseString)
        {
            logHeader(responseString);
            string line;

            var lineReader = new StringReader(responseString);

            //read stuff from first line like statuscode and protocol version
            var firstLine = lineReader.ReadLine();

            if (string.IsNullOrEmpty(firstLine))
            {
                HasError = true;
                ErrorMessage = "Proxy: protocol error invalid response, firstLine invalid";
                return;
            }

            var pos = firstLine.IndexOf(m_Space);


            if (pos <= 0 || firstLine.Length <= (pos + 2))
            {
                HasError = true;
                ErrorMessage = "Proxy: protocol error invalid response, firstLine invalid";
                return;
            }

            var httpProtocol = firstLine.Substring(0, pos);

            if (!m_ResponsePrefix.Equals(httpProtocol))
            {
                HasError = true;
                ErrorMessage = "Proxy: protocol error invalid HTTP Header: " + httpProtocol;
                return;
            }

            var statusPos = firstLine.IndexOf(m_Space, pos + 1);

            if (statusPos < 0)
            {
                HasError = true;
                ErrorMessage = "Proxy: protocol error invalid response statusPos < 0";
                return;
            }

            if (!HasError)
            {
                int.TryParse(firstLine.Substring(pos + 1, statusPos - pos - 1), out StatusCode);
            }

            //See if we have 
            while ((line = lineReader.ReadLine()) != null)
            {
                var headerParts = line.Split(); //@todo: this should work with Negotiate, NTLM, or Kerberos, should prefer Negotiate, fall back to NTLM/Kerberos
                if (headerParts[0] == "Proxy-Authenticate:" && headerParts.Length == 2)
                {
                    //found detecteable package
                    SupportedSecurityPackages[headerParts[1]] = true;

                }

                //Via header has useful stuff about the SPN sometimes
                if (headerParts[0] == "Via:" && headerParts.Length == 3)
                {
                    Via = headerParts[2];
                }

                if (headerParts[0] == "Proxy-Authenticate:" && headerParts.Length == 3)
                {
                    ReconnectNeeded = false;
                    HasChallangeToken = true;
                    SecurityPackage = headerParts[1];
                    ChallangeToken = headerParts[2];

                }


            }

            //debug which security packages we found
            foreach (string HashKey in SupportedSecurityPackages.Keys)
            {
                Debug.WriteLine("Security Package: " + HashKey + " : " + SupportedSecurityPackages[HashKey]);
            }

            if (StatusCode == 407)
            {
                AuthNeeded = true;


                if (HasChallangeToken)
                {
                    return;
                }
                else if (SupportedSecurityPackages.ContainsKey("NTLM"))
                {
                    SecurityPackage = "NTLM";
                }
                else if (SupportedSecurityPackages.ContainsKey("Kerberos"))
                {
                    SecurityPackage = "Kerberos";
                }
                else
                {
                    HasError = true;
                    ErrorMessage = "No supported security packages found for proxy.";
                    return;
                }

            }

        }




    }
}

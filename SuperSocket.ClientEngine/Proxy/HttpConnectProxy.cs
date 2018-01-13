using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using SuperSocket.ClientEngine;
using NSspi;
using NSspi.Contexts;
using NSspi.Credentials;
using System.Text.RegularExpressions;
using System.Threading;
using System.Collections;

namespace SuperSocket.ClientEngine.Proxy
{
    public class HttpConnectProxy : ProxyConnectorBase
    {
        class ConnectContext
        {
            public Socket Socket { get; set; }

            public SearchMarkState<byte> SearchState { get; set; }
        }
        

        private Hashtable supportedSecPackages = new Hashtable();
        //private HTTPProxyResponseHeader ProxyResponse;
        
        private string AuthToken = "";
        private string ChallangeToken = "";

        private const string m_RequestTemplate = "CONNECT {0}:{1} HTTP/1.1\r\nUser-Agent: {2}\r\nHost: {0}:{1}\r\nProxy-Connection: Keep-Alive\r\n\r\n";
        private const string m_NTLMRequestTemplate = "CONNECT {0}:{1} HTTP/1.1\r\nUser-Agent: {3}\r\nHost: {0}:{1}\r\nProxy-Authorization: {4} {2}\r\nProxy-Connection: Keep-Alive\r\n\r\n";

        private string userAgent = "ScreenMeet Windows Support Client";

        
        private EndPoint lastEndpoint;

        private string ProxyHostName = null;
        private Socket currentSocket;

        private string SecPackageName = null;
        private byte[] NSSPIClientToken = null;
        private byte[] NSSPIChallangeToken = null;
        private ClientCurrentCredential NSSPIclientCred;
        private SecurityStatus NSSPIclientStatus;
        private ClientContext NSSPIclient;
        private bool NSSPIInitiated = false;
        private string ProxyViaHeader = null;
        private bool isProxyHostname = false;

        private static byte[] m_LineSeparator;

        static HttpConnectProxy()
        {
            m_LineSeparator = ASCIIEncoding.GetBytes("\r\n\r\n");
        }

        private int m_ReceiveBufferSize;
        
        private void initNSSPI()
        {
            //singleton init for NSSPI API
            if (NSSPIInitiated)
            {
                return;
            }

            var packageName = SecPackageName;
            NSSPIclientCred = new ClientCurrentCredential(packageName);

            Debug.WriteLine("NSSPI Client Auth Principle: " + NSSPIclientCred.PrincipleName);

            byte[] NSSPIClientToken = null;
            byte[] NSSPIChallangeToken = null;
            
            NSSPIclient = new ClientContext(
                NSSPIclientCred,
                getBestSPNGuess(),//this is the SPN which is required in case we are using Kerberos. Needs to either be the machine name of the remote resource, or be in the format of HTTP/<hostname> - ip's don't work
                ContextAttrib.MutualAuth |
                //ContextAttrib.InitIdentify |
                //ContextAttrib.Confidentiality |
                ContextAttrib.ReplayDetect |
                ContextAttrib.SequenceDetect |
                ContextAttrib.Connection |
                ContextAttrib.Delegate
            );
            
            NSSPIInitiated = true;
        }


        //@todo: use better strategies to determine the SPN
        private string getBestSPNGuess()
        {

            if (isProxyHostname)
            {
                return "HTTP/" + ProxyHostName;
            } else if (ProxyViaHeader != null)
            {
                return ProxyViaHeader;
            } else
            {
                return "HTTP/" + ProxyHostName;
            }

            

        }

        private bool createNSSPIToken()
        {
            try
            {

                initNSSPI();

                if (ChallangeToken != "")
                {
                    NSSPIChallangeToken = Convert.FromBase64String(ChallangeToken);

                    Debug.WriteLine("[NSSPI] NTLM Challange token detected. Setting as server token: " + ChallangeToken);
                }

                NSSPIclientStatus = NSSPIclient.Init(NSSPIChallangeToken, out NSSPIClientToken);

                this.AuthToken = Convert.ToBase64String(NSSPIClientToken);

                return true;
            } catch (Exception e)
            {
                OnException("Failed to perform NSSPI Authentication while connecting to proxy. " +e.ToString());
                return false;
            }
            
        }

        public HttpConnectProxy(EndPoint proxyEndPoint, string targetHostName, string proxyHostName)
            : this(proxyEndPoint, 8192, targetHostName, proxyHostName)
        {
        }

        public HttpConnectProxy(EndPoint proxyEndPoint, int receiveBufferSize, string targetHostName, string proxyHostName)
            : base(proxyEndPoint, targetHostName)
        {
            m_ReceiveBufferSize = receiveBufferSize;
            ProxyHostName = proxyHostName;
        }

        public override void Connect(EndPoint remoteEndPoint)
        {
            if (remoteEndPoint == null)
            {
                throw new ArgumentNullException("remoteEndPoint");
            }

            if (!(remoteEndPoint is IPEndPoint || remoteEndPoint is DnsEndPoint))
            {
                throw new ArgumentException("remoteEndPoint must be IPEndPoint or DnsEndPoint", "remoteEndPoint");
            }

            //check if our hostname matches an ip address or not
            Match isProxyIpAddress = Regex.Match(ProxyHostName, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");

            Debug.WriteLine("[PROXY] Connecting to proxy: " + ProxyHostName);

            if (isProxyIpAddress.Success)
            {
                Debug.WriteLine("[PROXY] endpoint is IP endpoint");
            } else { 
                Debug.WriteLine("[PROXY] endpoint is a hostname/DNS endpoint");
                isProxyHostname = true;
            }

            try
            {
                //save reference to remote endpoint if we need to do back-and-forth connecting
                lastEndpoint = remoteEndPoint;
                ProxyEndPoint.ConnectAsync(null, ProcessConnect, remoteEndPoint);
            }
            catch (Exception e)
            {
                OnException(new Exception("[PROXY] Failed to connect proxy server", e));
            }
        }

        protected void sendSocketConnectPayload(Socket socket, object targetEndPoint, SocketAsyncEventArgs e)
        {

            if (e == null)
                e = new SocketAsyncEventArgs();

            string request;
            if (targetEndPoint is DnsEndPoint)
            {
                var targetDnsEndPoint = (DnsEndPoint)targetEndPoint;

                if (AuthToken != "")
                {
                    request = string.Format(m_NTLMRequestTemplate, targetDnsEndPoint.Host, targetDnsEndPoint.Port, AuthToken, userAgent, SecPackageName);
                }
                else
                {
                    request = string.Format(m_RequestTemplate, targetDnsEndPoint.Host, targetDnsEndPoint.Port, userAgent, SecPackageName);
                }

            }
            else
            {
                var targetIPEndPoint = (IPEndPoint)targetEndPoint;
                if (AuthToken != "")
                {
                    request = string.Format(m_NTLMRequestTemplate, targetIPEndPoint.Address, targetIPEndPoint.Port, AuthToken, userAgent, SecPackageName);
                }
                else
                {
                    request = string.Format(m_RequestTemplate, targetIPEndPoint.Address, targetIPEndPoint.Port, userAgent, SecPackageName);
                }
            }

            Debug.WriteLine("\r\n[***PROXY REQUEST HEADER START***]:\r\n" + request);

            var requestData = ASCIIEncoding.GetBytes(request);

            Debug.WriteLine("[***PROXY REQUEST HEADER END***]");

            e.Completed += AsyncEventArgsCompleted;
            e.UserToken = new ConnectContext { Socket = socket, SearchState = new SearchMarkState<byte>(m_LineSeparator) };
            currentSocket = socket;
            e.SetBuffer(requestData, 0, requestData.Length);

            StartSend(socket, e);
        }

        protected override void ProcessConnect(Socket socket, object targetEndPoint, SocketAsyncEventArgs e, Exception exception)
        {

            Debug.WriteLine("ProxyConnect - attempting to connect to proxy");

            if (exception != null)
            {
                OnException(exception);
                return;
            }

            if (e != null)
            {
                if (!ValidateAsyncResult(e))
                    return;
            }

            if (socket == null)
            {
                OnException(new SocketException((int)SocketError.ConnectionAborted));
                return;
            }

            sendSocketConnectPayload(socket, targetEndPoint, e);


        }

        protected override void ProcessSend(SocketAsyncEventArgs e)
        {
            if (!ValidateAsyncResult(e))
                return;

            var context = (ConnectContext)e.UserToken;

            var buffer = new byte[m_ReceiveBufferSize];
            e.SetBuffer(buffer, 0, buffer.Length);

            StartReceive(context.Socket, e);
        }

        protected override void ProcessReceive(SocketAsyncEventArgs e)
        {
            if (!ValidateAsyncResult(e))
                return;

            var context = (ConnectContext)e.UserToken;

            int prevMatched = context.SearchState.Matched;

            int result = e.Buffer.SearchMark(e.Offset, e.BytesTransferred, context.SearchState);

            if (result < 0)
            {
                int total = e.Offset + e.BytesTransferred;

                if(total > m_ReceiveBufferSize)
                {
                    OnException("receive buffer size has been exceeded");
                    return;
                }

                e.SetBuffer(total, m_ReceiveBufferSize - total);
                StartReceive(context.Socket, e);
                return;
            }

            int responseLength = prevMatched > 0 ? (e.Offset - prevMatched) : (e.Offset + result);

            //if (e.Offset + e.BytesTransferred > responseLength + m_LineSeparator.Length)
            //{
            //    OnException("protocol error: more data has been received");
            //    return;
            //}

            var responseString = ASCIIEncoding.GetString(e.Buffer, 0, responseLength);

            var lineReader = new StringReader(ASCIIEncoding.GetString(e.Buffer, 0, responseLength));
            
            var proxyResponse = new HTTPProxyResponseHeader(ASCIIEncoding.GetString(e.Buffer, 0, responseLength));

            //if something went wrong during connect attempt
            if (proxyResponse.HasError)
            {
                Debug.WriteLine("[PROXY CONNECT ERROR] " + proxyResponse.ErrorMessage);
                OnException(proxyResponse.ErrorMessage);
                return;
            }

            if (proxyResponse.AuthNeeded) //we got a 407 so we need to do some kinda handshake
            {

                if (proxyResponse.ReconnectNeeded)
                {
                    //this is the initial rejected connect attempt which has announced we need to authenticate and told us which security packs it supports.

                    //we chose our preferred auth strategy and set it for the connector class
                    SecPackageName = proxyResponse.SecurityPackage;

                    //create the nsspi token
                    var success = createNSSPIToken();

                    if (success)
                    {
                        //re-connect
                        Connect(lastEndpoint);
                    }
                    
                    return; //exit method

                } else if (proxyResponse.HasChallangeToken)
                {
                    //we have our challange token, which we must not turn into the 3rd token and re-send the "CONNECT" payload while maintaining the same socket connection.


                    //create the challange response (final) token
                    ChallangeToken = proxyResponse.ChallangeToken; //sets the base64 token


                    //sets our AuthToken to the stage 3 token
                    var success = createNSSPIToken();

                    if (success)
                    {
                        //re-send the connect payload, this time with the complete NTLM token
                        sendSocketConnectPayload(context.Socket, lastEndpoint, null);
                    }

                   
                    return;
                }

            } else
            {
                Debug.WriteLine("Proxy Connection Successful");
            }
           
            OnCompleted(new ProxyEventArgs(context.Socket, TargetHostHame));
        }
    }
}

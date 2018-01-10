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

namespace SuperSocket.ClientEngine.Proxy
{
    public class HttpConnectProxy : ProxyConnectorBase
    {
        class ConnectContext
        {
            public Socket Socket { get; set; }

            public SearchMarkState<byte> SearchState { get; set; }
        }

        private string NTLMToken = "";
        private string NTLMChallangeToken = "";

        private const string m_RequestTemplate = "CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\nProxy-Connection: Keep-Alive\r\n\r\n";
        private const string m_NTLMRequestTemplate = "CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\nproxy-Authorization: NTLM {2}\r\nProxy-Connection: Keep-Alive\r\n\r\n";


        private const string m_ResponsePrefix = "HTTP/1.1";
        private const char m_Space = ' ';
        private EndPoint lastEndpoint;

        private byte[] NTLMClientToken = null;
        private byte[] serverToken = null;

        private ClientCurrentCredential NSSPIclientCred;
        private SecurityStatus NSSPIclientStatus;
        private ClientContext NSSPIclient;
        private bool NSSPIInitiated = false;




        private static byte[] m_LineSeparator;

        static HttpConnectProxy()
        {
            m_LineSeparator = ASCIIEncoding.GetBytes("\r\n\r\n");
        }

        private int m_ReceiveBufferSize;

        public HttpConnectProxy(EndPoint proxyEndPoint)
            : this(proxyEndPoint, 8192, null)
        {

        }
        private void initNTLMClientAuth()
        {
            //singleton init
            if (NSSPIInitiated)
            {
                return;
            }

            var packageName = "NTLM";
            NSSPIclientCred = new ClientCurrentCredential(packageName);

            Debug.WriteLine("NSSPI Client Auth Principle: " + NSSPIclientCred.PrincipleName);

            byte[] NTLMClientToken = null;
            byte[] serverToken = null;
            
            NSSPIclient = new ClientContext(
                    NSSPIclientCred,
                    NSSPIclientCred.PrincipleName,
                    ContextAttrib.MutualAuth |
                    ContextAttrib.InitIdentify |
                    ContextAttrib.Confidentiality |
                    ContextAttrib.ReplayDetect |
                    ContextAttrib.SequenceDetect |
                    ContextAttrib.Connection |
                    ContextAttrib.Delegate
                );

            NSSPIInitiated = true;
        }

        private void setNTLMToken()
        {
            initNTLMClientAuth();

            if (NTLMChallangeToken != "")
            {
                serverToken = Convert.FromBase64String(NTLMChallangeToken);
                Debug.WriteLine("NTLM Challange token detected. Setting server token: " + NTLMChallangeToken);
            }

            //while (true)
            //{
            NSSPIclientStatus = NSSPIclient.Init(serverToken, out NTLMClientToken);
            Debug.WriteLine("NSSPI ClientStatus: " + NSSPIclientStatus.ToString());
                //if (clientStatus != SecurityStatus.ContinueNeeded) { break; }
            //}
            
            //
            this.NTLMToken = Convert.ToBase64String(NTLMClientToken);
            Debug.WriteLine("NTLMToken: " + this.NTLMToken);
        }

        public HttpConnectProxy(EndPoint proxyEndPoint, string targetHostName)
            : this(proxyEndPoint, 8192, targetHostName)
        {
        }

        public HttpConnectProxy(EndPoint proxyEndPoint, int receiveBufferSize, string targetHostName)
            : base(proxyEndPoint, targetHostName)
        {
            m_ReceiveBufferSize = receiveBufferSize;
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

            try
            {
                //save reference to remote endpoint if we need to do back-and-forth connecting
                lastEndpoint = remoteEndPoint;
                ProxyEndPoint.ConnectAsync(null, ProcessConnect, remoteEndPoint);
            }
            catch (Exception e)
            {
                OnException(new Exception("Failed to connect proxy server", e));
            }
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
            
            if (e == null)
                e = new SocketAsyncEventArgs();

            setNTLMToken();

            string request;
            if (targetEndPoint is DnsEndPoint)
            {
                var targetDnsEndPoint = (DnsEndPoint)targetEndPoint;
                request = string.Format(m_NTLMRequestTemplate, targetDnsEndPoint.Host, targetDnsEndPoint.Port, NTLMToken);
            }
            else
            {
                var targetIPEndPoint = (IPEndPoint)targetEndPoint;
                request = string.Format(m_NTLMRequestTemplate, targetIPEndPoint.Address, targetIPEndPoint.Port, NTLMToken);
            }

            Debug.WriteLine("PROXY Request:--------------\r\n" + request);

            var requestData = ASCIIEncoding.GetBytes(request);

            Debug.WriteLine("----------------------------\r\n" + request);

            e.Completed += AsyncEventArgsCompleted;
            e.UserToken = new ConnectContext { Socket = socket, SearchState = new SearchMarkState<byte>(m_LineSeparator) };
            e.SetBuffer(requestData, 0, requestData.Length);

            StartSend(socket, e);
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

            var lineReader = new StringReader(ASCIIEncoding.GetString(e.Buffer, 0, responseLength));

            var line = lineReader.ReadLine();

            if (string.IsNullOrEmpty(line))
            {

                Debug.WriteLine("Proxy: Null String");

                OnException("protocol error: invalid response");
                return;
            }

            //HTTP/1.1 2** OK
            var pos = line.IndexOf(m_Space);

            if (pos <= 0 || line.Length <= (pos + 2))
            {
                Debug.WriteLine("Proxy: protocol error invalid response");
                OnException("protocol error: invalid response");
                return;
            }

            var httpProtocol = line.Substring(0, pos);

            if (!m_ResponsePrefix.Equals(httpProtocol))
            {
                Debug.WriteLine("Proxy: protocol error invalid protocol");
                OnException("protocol error: invalid protocol");
                return;
            }

            var statusPos = line.IndexOf(m_Space, pos + 1);

            if (statusPos < 0)
            {
                Debug.WriteLine("Proxy: protocol error invalid response statusPos < 0");
                OnException("protocol error: invalid response");
                return;
            }

            int statusCode;
            //Status code should be 2**
            if (!int.TryParse(line.Substring(pos + 1, statusPos - pos - 1), out statusCode) || (statusCode > 299 || statusCode < 200))
            {

                if (statusCode == 407)
                {
                    Debug.WriteLine("Proxy server requires authentication. Response:");
                    Debug.WriteLine(line);
                    while ((line = lineReader.ReadLine()) != null)
                    {
                        Debug.WriteLine(line);
                        var headerParts = line.Split();
                        if (headerParts[0] == "Proxy-Authenticate:" && headerParts[1] == "NTLM" && headerParts.Length == 3)
                        {
                            Debug.WriteLine("Proxy-Authenticate challange response found. Auth Protocol: " + headerParts[1]);
                            Debug.WriteLine("Challange Token: " + headerParts[2]);
                            NTLMChallangeToken = headerParts[2];

                            Connect(lastEndpoint);

                            break;

                        }
                    }

                   

                    return;

                } else
                {
                    Debug.WriteLine("Proxy server refused connection. Full Response:");
                    Debug.WriteLine(line);
                    Debug.WriteLine(lineReader.ReadToEnd());
                    OnException("the proxy server refused the connection");
                    return;
                }

                
            }

            OnCompleted(new ProxyEventArgs(context.Socket, TargetHostHame));
        }
    }
}

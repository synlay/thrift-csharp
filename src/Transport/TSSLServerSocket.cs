/// Anthony Abate
/// Based off TServerSocket.cs with some modifications and MSDN
/// Ran Style Cop for documentation, spacing
/// http://msdn.microsoft.com/en-us/library/system.net.security.sslstream.aspx

namespace Thrift.Transport
{
    using System;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// SSL Server Socket Wrapper Class
    /// </summary>
    public class TSSLServerSocket : TServerTransport
    {
        /// <summary>
        /// Logger for class
        /// </summary>
		public delegate void LogDelegate(string str);
		protected LogDelegate logDelegate;

        /// <summary>
        /// The Tcp Server
        /// </summary>
        private TcpListener server = null;

        /// <summary>
        /// SSL Certificate
        /// </summary>
        private X509Certificate serverCertificate;

		protected static void DefaultLogDelegate(string s)
		{
			Console.Error.WriteLine(s);
		}

        /// <summary>
        /// Initializes a new instance of the TSSLServerSocket class from an existing TCP Socket + Certificate 
        /// </summary>
        /// <param name="listener">TCP Listener Server</param>
        /// <param name="certificate">SSL Certificate</param>
        public TSSLServerSocket(TcpListener listener, string certificate)
            : this(listener, 0, X509Certificate.CreateFromCertFile(certificate), DefaultLogDelegate)
        {
        }
        public TSSLServerSocket(TcpListener listener, string certificate, LogDelegate logDelegate)
            : this(listener, 0, X509Certificate.CreateFromCertFile(certificate))
        {
        }

        /// <summary>
        /// Initializes a new instance of the TSSLServerSocket class from an existing TCP Socket + Certificate 
        /// </summary>
        /// <param name="listener">TCP Listener Server</param>
        /// <param name="clientTimeout">Send/Recv Timeout</param>
        /// <param name="certificate">SSL Certificate</param>
        public TSSLServerSocket(TcpListener listener, int clientTimeout, X509Certificate certificate)
            : this(listener, clientTimeout, certificate, DefaultLogDelegate)
        {
        }
        public TSSLServerSocket(TcpListener listener, int clientTimeout, X509Certificate certificate, LogDelegate logDelegate)
        {
            logDelegate("creating ssl server socket: LocalEndpoint:" + listener.LocalEndpoint + " timeout:" + clientTimeout + " cert:" + certificate);

            listener.Server.ReceiveTimeout = clientTimeout;
            listener.Server.SendTimeout = clientTimeout;
            this.server = listener;
            this.serverCertificate = certificate;
			this.logDelegate = logDelegate;
        }

        /// <summary>
        /// Initializes a new instance of the TSSLServerSocket class on a TCP Port with a Certificate file
        /// </summary>
        /// <param name="port">TCP Port to listen on</param>
        /// <param name="certificate">Filename of SSL Cert</param>
        public TSSLServerSocket(int port, string certificate)
            : this(port, certificate, DefaultLogDelegate)
        {
        }
        public TSSLServerSocket(int port, string certificate, LogDelegate logDelegate)
            : this(port, 0, certificate, logDelegate)
        {
        }

        /// <summary>
        /// Initializes a new instance of the TSSLServerSocket class  on a TCP Port with a Certificate file
        /// </summary>
        /// <param name="port">TCP Port to listen on</param>
        /// <param name="clientTimeout">Send/Recv Timeout</param>
        /// <param name="certificate">Filename of SSL Cert</param>
        public TSSLServerSocket(int port, int clientTimeout, string certificate)
            : this(new TcpListener(System.Net.IPAddress.Any, port), clientTimeout, X509Certificate.CreateFromCertFile(certificate), DefaultLogDelegate)
        {
        }
        public TSSLServerSocket(int port, int clientTimeout, string certificate, LogDelegate logDelegate)
            : this(new TcpListener(System.Net.IPAddress.Any, port), clientTimeout, X509Certificate.CreateFromCertFile(certificate), logDelegate)
        {
        }

        /// <summary>
        /// Starts Listen / Accept
        /// </summary>
        public override void Listen()
        {
            ////TODO: is this even needed?  can the base class handle this?

            if (this.server != null)
            {
                try
                {
                    this.server.Start();
                }
                catch (SocketException sx)
                {
                    logDelegate(sx.ToString());
                }
            }
        }
                        
        /// <summary>
        /// Stops the Server
        /// </summary>
        public override void Close()
        {
            ////TODO: is this even needed?  can the base class handle this?

            if (this.server != null)
            {
                try
                {
                    this.server.Stop();
                }
                catch (SocketException sx)  
                {
                    //// The only type of exception stop can throw is socketexception
                    logDelegate(sx.ToString());
                }

                this.server = null;
            }
        }

        /// <summary>
        /// Callback for Accept Implementation
        /// </summary>
        /// <returns>Transport Object</returns>
        protected override TTransport AcceptImpl()
        {
            if (this.server == null)
            {
                throw new TTransportException(TTransportException.ExceptionType.NotOpen, "No underlying server socket.");
            }

            try
            {
                TcpClient client = this.server.AcceptTcpClient();

                //wrap the client in an SSL Socket passing in the SSL cert
                TSSLSocket socket = new TSSLSocket(client, this.serverCertificate);

                //setup the socket as an SSL Server
                socket.SetupServer();

                return socket;
            }
            catch (Exception ex)
            {
                logDelegate(ex.ToString());
                throw new TTransportException(ex.ToString());
            }
        }
    }
}

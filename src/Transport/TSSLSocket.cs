/// Anthony Abate
/// Based off TSocket.cs with some modifications and MSDN
/// Ran Style Cop for documentation, spacing
/// http://msdn.microsoft.com/en-us/library/system.net.security.sslstream.aspx

namespace Thrift.Transport
{
    using System;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// SSL Socket Wrapper class
    /// </summary>
    public class TSSLSocket : TStreamTransport
    {
        /// <summary>
        /// Internal logger for class
        /// </summary>
		public delegate void LogDelegate(string str);
		protected LogDelegate logDelegate;

        /// <summary>
        /// Internal TCP Client
        /// </summary>
        private TcpClient client = null;
        
		/// <summary>
        /// Internal Hostname
        /// </summary>
		// TODO: this.host correct???
        private string host = null;

        /// <summary>
        /// Internal SSL Stream for IO
        /// </summary>
        private SslStream sslStream = null;

        /// <summary>
        /// Internal SSL Cert for Socket.  This will be the server or client cert depending on setup.
        /// </summary>
        private X509Certificate certificate;

        /// <summary>
        /// IO Timeout
        /// </summary>
        private int timeout = 0;

		protected static void DefaultLogDelegate(string s)
		{
			Console.Error.WriteLine(s);
		}

        /// <summary>
        /// Initializes a new instance of the TSSLSocket class from an existing TCP Client
        /// </summary>
        /// <param name="client">existing TCP Client</param>
        /// <param name="cert">SSL Certificate</param>
        public TSSLSocket(TcpClient client, X509Certificate cert)
            :this (client, 0, cert, DefaultLogDelegate)
        {
        }
        public TSSLSocket(TcpClient client, X509Certificate cert, LogDelegate logDelegate)
            :this (client, 0, cert, logDelegate)
        {
        }

        /// <summary>
        /// Initializes a new instance of the TSSLSocket class for a new TCP Client        
        /// </summary>
        /// <param name="host">Hostname of server</param>
        /// <param name="port">Host port</param>
        /// <param name="timeout">IO Timeouts</param>
        /// <param name="cert">SSl Certificate Filename</param>
        public TSSLSocket(string host, int port, int timeout, string cert)
            : this(new TcpClient(host, port), timeout, X509Certificate.CreateFromCertFile(cert), DefaultLogDelegate)
        {
        }
        public TSSLSocket(string host, int port, int timeout, string cert, LogDelegate logDelegate)
            : this(new TcpClient(host, port), timeout, X509Certificate.CreateFromCertFile(cert), logDelegate)
        {
			// TODO: this.host correct???
			this.host = host;
        }

        /// <summary>
        /// Initializes a new instance of the TSSLSocket class from an existing TCP Client        
        /// </summary>
        /// <param name="tcpclient">existing TCP Client</param>
        /// <param name="iotimeout">IO Timeouts</param>
        /// <param name="cert">SSl Certificate</param>
        public TSSLSocket(TcpClient tcpclient, int iotimeout, X509Certificate cert)
            : this(tcpclient, iotimeout, cert, DefaultLogDelegate)
        {
        }
        public TSSLSocket(TcpClient tcpclient, int iotimeout, X509Certificate cert, LogDelegate logDelegate)
        {
            this.client = tcpclient;
			// TODO: correct???
            this.Timeout = iotimeout;
            //this.Timeout = this.iotimeout;
            this.certificate = cert;
			this.logDelegate = logDelegate;
        }

        /// <summary>
        /// Sets Send / Recv Timeout for IO
        /// </summary>
        public int Timeout
        {
            set
            {
                this.client.ReceiveTimeout = this.client.SendTimeout = this.timeout = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether TCP Client is Cpen 
        /// </summary>
        public override bool IsOpen
        {
            get
            {
                if (this.client == null)
                {
                    return false;
                }

                return this.client.Connected;
            }
        }

        /// <summary>
        /// Callback for certificate validation
        /// </summary>
        /// <param name="sender">object requesting validation</param>
        /// <param name="certificate">cert to valdate</param>
        /// <param name="chain">chain of certs</param>
        /// <param name="sslPolicyErrors">any errors in the policy</param>
        /// <returns>Validate or not</returns>
        public static bool ValidateCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            SslPolicyErrors errors = sslPolicyErrors;
            if (errors != SslPolicyErrors.None)
            {
				DefaultLogDelegate("Certificate error: " + errors);
            }

            if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.RemoteCertificateChainErrors)
            {
				DefaultLogDelegate("Certificate error: Certificate chain empty. Self signed certificate? but still continued");
                errors -= SslPolicyErrors.RemoteCertificateChainErrors;
            }

            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) == SslPolicyErrors.RemoteCertificateNameMismatch)
            {
                errors -= SslPolicyErrors.RemoteCertificateNameMismatch;
            }

            if (errors == SslPolicyErrors.None)
            {
                return true;
            }
			DefaultLogDelegate("Certificate error: " + sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

        /// <summary>
        /// Sets up Socket as an SSL Client
        /// </summary>
        public override void Open()
        {
            if (!this.IsOpen)
            {
                throw new TTransportException(TTransportException.ExceptionType.NotOpen, "Socket Not Open");
            }

            this.SetupClient(host);
        }

        /// <summary>
        /// Closes SSL Socket
        /// </summary>
        public override void Close()
        {
            base.Close();

            if (this.client != null)
            {
                this.client.Close();
                this.client = null;
            }

            if (this.sslStream != null)
            {
                this.sslStream.Close();
                this.sslStream = null;
            }
        }

        /// <summary>
        /// Configure this Socket as an SSL Client
        /// </summary>
        /// <param name="targethost">Server to validate cert</param>
        public void SetupClient(string targethost)
        {
            this.Setup(targethost);
        }

        /// <summary>
        /// Configure ths socket as an SSL Server
        /// </summary>
        public void SetupServer()
        {
            this.Setup(null);
        }

        /// <summary>
        /// Diagnostic Info
        /// </summary>
        /// <param name="stream">SSL Stream</param>
        protected static void DisplaySecurityLevel(SslStream stream)
        {
			DefaultLogDelegate("Cipher: " + stream.CipherAlgorithm + " strength " + stream.CipherStrength);
			DefaultLogDelegate("Hash: " + stream.HashAlgorithm + " strength " + stream.HashStrength);
			DefaultLogDelegate("Key exchange: " + stream.KeyExchangeAlgorithm + " strength " + stream.KeyExchangeStrength);
			DefaultLogDelegate("Protocol: " + stream.SslProtocol);
        }

        /// <summary>
        /// Diagnostic Info
        /// </summary>
        /// <param name="stream">SSL Stream</param>
        protected static void DisplaySecurityServices(SslStream stream)
        {
            DefaultLogDelegate("Is authenticated: " + stream.IsAuthenticated + " as server? " + stream.IsServer);
            DefaultLogDelegate("IsSigned: " + stream.IsSigned);
            DefaultLogDelegate("Is Encrypted: " + stream.IsEncrypted);
        }

        /// <summary>
        /// Diagnostic Info
        /// </summary>
        /// <param name="stream">SSL Stream</param>
        protected static void DisplayStreamProperties(SslStream stream)
        {
            DefaultLogDelegate("Can read: " + stream.CanRead + ", write " + stream.CanWrite);
            DefaultLogDelegate("Can timeout: " + stream.CanTimeout);
        }

        /// <summary>
        /// Diagnostic Info
        /// </summary>
        /// <param name="stream">SSL Stream</param>
        protected static void DisplayCertificateInformation(SslStream stream)
        {
            DefaultLogDelegate("Certificate revocation list checked: " + stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;

            if (stream.LocalCertificate != null)
            {
                DefaultLogDelegate("Local cert was issued to " + localCertificate.Subject + " and is valid from " + localCertificate.GetEffectiveDateString() + " until " + localCertificate.GetExpirationDateString() + ".");
            }
            else
            {
                DefaultLogDelegate("Local certificate is null.");
            }

            X509Certificate remoteCertificate = stream.RemoteCertificate;

            if (stream.RemoteCertificate != null)
            {
                DefaultLogDelegate("Remote cert was issued to " + remoteCertificate.Subject + " and is valid from " + remoteCertificate.GetEffectiveDateString() + " until " + remoteCertificate.GetExpirationDateString() + ".");
            }
            else
            {
                DefaultLogDelegate("Remote certificate is null.");
            }
        }

        /// <summary>
        /// Confgigures the Socket for SSL
        /// </summary>
        /// <param name="targethost">Host name of Server (used by client). Set to null if confinguring a server</param>
        protected void Setup(string targethost)
        {
            try
            {
                ////TODO: setup 2 way certificate handshake

                if (host == null)
                {
                    this.sslStream = new SslStream(this.client.GetStream(), false);
                    this.sslStream.AuthenticateAsServer(this.certificate, false, SslProtocols.Tls, true);
                }
                else
                {
                    ////X509CertificateCollection clientCertificatecollection = new X509CertificateCollection();
                    ////clientCertificatecollection.Add(Certificate);
                    ////sslStream.AuthenticateAsClient(targethost, clientCertificatecollection, SslProtocols.Tls, false);

                    this.sslStream = new SslStream(this.client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateCertificate), null);
                    this.sslStream.AuthenticateAsClient(targethost);
                }

                // Display the properties and settings for the authenticated stream.
                DisplaySecurityLevel(this.sslStream);
                DisplaySecurityServices(this.sslStream);
                DisplayCertificateInformation(this.sslStream);
                DisplayStreamProperties(this.sslStream);

                this.sslStream.ReadTimeout = this.timeout;
                this.sslStream.WriteTimeout = this.timeout;

                this.inputStream = this.sslStream;
                this.outputStream = this.sslStream;
            }
            catch (AuthenticationException e)
            {
                DefaultLogDelegate(e.ToString());
                DefaultLogDelegate("Authentication failed - closing the connection.");

                this.sslStream.Close();
                this.client.Close();
            }
        }
    }
}

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ShiftingAllegiances
{
	internal class Server
	{
		private const int HeaderSize = 256;
		private const int BufferSize = 2048;
		private const string LogsDirectory = "Logs";

		private int _port;
		private string _certificatePath;

		public Server(int port, string certificatePath)
		{
			_port = port;
			_certificatePath = certificatePath;
		}

		public void Run()
		{
			if (!Directory.Exists(LogsDirectory))
			{
				Directory.CreateDirectory(LogsDirectory);
				Console.WriteLine("Created logging directory");
			}
			var serverCertificate = new X509Certificate(_certificatePath, "");
			var address = IPAddress.Parse("127.0.0.1");
			var localEndpoint = new IPEndPoint(address, _port);
			var listener = new TcpListener(localEndpoint);
			listener.Start();
			Console.WriteLine($"Listening for TCP connections on {address}");
			while (true)
			{
				var localClient = listener.AcceptTcpClient();
				ProcessClient(localClient, serverCertificate);
			}
		}

		private async void ProcessClient(TcpClient localClient, X509Certificate serverCertificate)
		{
			try
			{
				await ProcessClientInner(localClient, serverCertificate);
			}
			catch (Exception exception)
			{
				Console.WriteLine($"Error: {exception}");
			}
		}

		private async Task ProcessClientInner(TcpClient localClient, X509Certificate serverCertificate)
		{
			Console.WriteLine($"Received a connection from {localClient.Client.RemoteEndPoint}");
			var now = DateTime.Now;
			var stream = localClient.GetStream();
			var buffer = new byte[HeaderSize];
			int offset = 0;
			int bytesToRead = HeaderSize;
			while (bytesToRead > 0)
			{
				int bytesRead = stream.Read(buffer, offset, bytesToRead);
				if (bytesRead == 0)
					break;
				bytesToRead -= bytesRead;
			}
			if (bytesToRead > 0)
				throw new ApplicationException($"Failed to read header ({bytesToRead} bytes left)");
			int nonZeroByteCount = 0;
			for (int i = 1; i < buffer.Length; i++)
			{
				if (buffer[i] == 0)
					break;
				nonZeroByteCount = i - 1;
			}
			string header = Encoding.ASCII.GetString(buffer, 0, nonZeroByteCount);
			var pattern = new Regex(@"^(?<host>.+?):(?<port>\d+)$");
			var match = pattern.Match(header);
			if (!match.Success)
			{
				throw new ApplicationException($"Failed to extract host and port from header: {header}");
			}
			string host = match.Groups["host"].Value;
			int port = int.Parse(match.Groups["port"].Value);
			Console.WriteLine($"Received a request to connect to {host}:{port}");
			var remoteClient = new TcpClient();
			remoteClient.Connect(host, port);
			var remoteStream = new SslStream(remoteClient.GetStream(), false, new RemoteCertificateValidationCallback(TrustAllCertificates));
			remoteStream.AuthenticateAsClient(host);
			var localStream = new SslStream(localClient.GetStream(), false);
			localStream.AuthenticateAsServer(serverCertificate);
			string timestamp = now.ToString("yyyy-MM-dd HH-mm-ss");
			var ipEndPoint = (IPEndPoint)localClient.Client.RemoteEndPoint;
			string fileName = $"{timestamp} {ipEndPoint.Port}.log";
			string logPath = Path.Combine(LogsDirectory, fileName);
			using (var logStream = new FileStream(logPath, FileMode.CreateNew))
			{
				var localReadBuffer = new byte[BufferSize];
				var remoteReadBuffer = new byte[BufferSize];
				var localReadTask = localStream.ReadAsync(localReadBuffer, 0, BufferSize);
				var remoteReadTask = remoteStream.ReadAsync(remoteReadBuffer, 0, BufferSize);
				while (localClient.Connected && remoteClient.Connected)
				{
					Task.WaitAny(localReadTask, remoteReadTask);
					localReadTask = await ProcessReadTask(localStream, localReadBuffer, localReadTask, remoteStream, "C -> S", logStream);
					remoteReadTask = await ProcessReadTask(remoteStream, remoteReadBuffer, remoteReadTask, localStream, "S -> C", logStream);
				}
			}
		}

		private static async Task<Task<int>> ProcessReadTask(SslStream readStream, byte[] readBuffer, Task<int> readTask, SslStream writeStream, string logPrefix, FileStream logStream)
		{
			if (readTask.IsCompleted && !readTask.IsFaulted)
			{
				int bytesRead = readTask.Result;
				if (bytesRead > 0)
				{
					var remoteWriteBuffer = new byte[bytesRead];
					Array.Copy(readBuffer, remoteWriteBuffer, bytesRead);
					var now = DateTime.UtcNow;
					string timestamp = now.ToString("yyyy-MM-dd HH:mm:ss");
					string prefixString = $"{timestamp} {logPrefix} ({bytesRead} bytes)\n";
					if (logStream.Length > 0)
						prefixString = $"\n{prefixString}";
					var prefixBuffer = Encoding.ASCII.GetBytes(prefixString);
					await logStream.WriteAsync(prefixBuffer, 0, prefixBuffer.Length);
					await logStream.WriteAsync(remoteWriteBuffer, 0, bytesRead);
					await writeStream.WriteAsync(remoteWriteBuffer, 0, bytesRead);
					readTask = readStream.ReadAsync(readBuffer, 0, BufferSize);
				}
			}

			return readTask;
		}

		private bool TrustAllCertificates(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
		{
			return true;
		}
	}
}

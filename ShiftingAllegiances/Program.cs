using System;
using System.Reflection;

namespace ShiftingAllegiances
{
	internal class Program
	{
		static void Main(string[] arguments)
		{
			if (arguments.Length != 2)
			{
				var assembly = Assembly.GetExecutingAssembly();
				var name = assembly.GetName();
				Console.WriteLine("Usage:");
				Console.WriteLine($"{name.Name} <port> <path to .pfx file>");
				return;
			}
			int port = int.Parse(arguments[0]);
			string pfxPath = arguments[1];
			var tlsProxy = new TlsProxy(port, pfxPath);
			tlsProxy.Run();
		}
	}
}

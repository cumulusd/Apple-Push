using Microsoft.VisualBasic;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

public class APNS
{

	private X509Certificate2 _Certificate = null;
	private X509Certificate2Collection _Certificates = new X509Certificate2Collection();
	private string SandboxAddress = "gateway.sandbox.push.apple.com"; // using the sand box service

	private string deviceToken = "YOUR DEVICE TOKEN HERE";
	public APNS(string p12FilePath, string p12FilePassword)
	{
		_Certificate = new X509Certificate2(File.ReadAllBytes(p12FilePath), p12FilePassword);
		_Certificates.Add(_Certificate);

		SslStream sslStream = null;
		TcpClient client = new TcpClient();

		client.Connect(SandboxAddress, 2195);
		sslStream = new SslStream(client.GetStream, false, new RemoteCertificateValidationCallback(validateServerCert), new LocalCertificateSelectionCallback(provideCertificate));

		sslStream.AuthenticateAsClient(SandboxAddress, _Certificates, Security.Authentication.SslProtocols.Tls, false);

		MemoryStream memoryStream = new MemoryStream();
		BinaryWriter writer = new BinaryWriter(memoryStream);
		writer.Write(Convert.ToByte(0));
		//The command
		writer.Write(Convert.ToByte(0));
		//The first byte of the deviceId length (big-endian first byte)
		writer.Write(Convert.ToByte(32));
		//The deviceId length (big-endian second byte)
		writer.Write(hexStringToByteArray(deviceToken));
		String payload = "{\"aps\":{\"alert\":\"Hello World\",\"badge\":0,\"sound\":\"default\"}}";
		writer.Write(Convert.ToByte(0));
		writer.Write(Convert.ToByte(payload.Length));
		byte[] b1 = System.Text.Encoding.UTF8.GetBytes(payload);
		writer.Write(b1);
		writer.Flush();
		byte[] array = memoryStream.ToArray();
		sslStream.Write(array);
		sslStream.Flush();
		client.Close();

		sslStream.Close();
		sslStream.Dispose();
		sslStream = null;

		client.Close();
		client = null;
	}

	private byte[] hexStringToByteArray(String s)
	{
		byte[] bHexString = new byte[deviceToken.Length / 2];
		for (int i = 0; i <= bHexString.Length - 1; i++) {
			bHexString(i) = byte.Parse(deviceToken.Substring(i * 2, 2), Globalization.NumberStyles.HexNumber);
		}
		return bHexString;
	}

	private bool validateServerCert(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
	{
		return true;
	}

	private X509Certificate2 provideCertificate(object sender, string targetHost, X509Certificate2Collection localCertificates, X509Certificate2 remoteCertificate, string[] acceptableIssuers)
	{
		return _Certificate;
	}

}


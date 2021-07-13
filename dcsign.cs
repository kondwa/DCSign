using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

class DCSign{
	/*
		Digital Certificate Signing Tool
		Author:	Kondwani Hara
		Email:
			khara@malswitch.mw (Work)
			kondwa@gmail.com (Personal)
		Phone:
			0999 477 737
			0888 477 737
		- Sign a document.
		- Verify a signed document. 
		- Extract a signed document.
		
		Tested certificate types: .pfx, p12. 
	*/
	private X509Certificate2 certificate;

	public DCSign(string certpath, string certpass){
		try{
			this.certificate = new X509Certificate2(certpath,certpass);
		}catch(Exception){}
	}
	public void Sign(string filepath){
		try{
			byte[] data = File.ReadAllBytes(filepath);
			string signedFile = Path.ChangeExtension(filepath, ".p7s");
			// setup data for signing
			ContentInfo content = new ContentInfo(data);
			SignedCms signedCms = new SignedCms(content);
			CmsSigner signer = new CmsSigner(this.certificate);
			signer.IncludeOption = X509IncludeOption.EndCertOnly;
			// create a signature.
			signedCms.ComputeSignature(signer);
			// encode signed message.
			byte[] signedData = signedCms.Encode();
			// write signed data to file in bytes 
			File.WriteAllBytes(signedFile,signedData);
		}catch(Exception){}
	}
	public bool Verify(string signedFile) {
		try{
			byte[] signedData = File.ReadAllBytes(signedFile);
			SignedCms signedCms = new SignedCms();
			// decode signed message.
			signedCms.Decode(signedData);
			// verify signature
			signedCms.CheckSignature(new X509Certificate2Collection(this.certificate), true);
			return true;	
		}catch(Exception){
			return false;
		}
	}
	public void Extract(string signedFile, string outputFile){
		try{
			byte[] signedcontent = File.ReadAllBytes(signedFile);
			SignedCms signedCms = new SignedCms();
			// decode signature.
			signedCms.Decode(signedcontent);
			// extract content.
			byte[] content = signedCms.ContentInfo.Content;
			File.WriteAllBytes(outputFile,content);
		}catch(Exception){}
	}
}
class Program{
	static void Main(string[] args){
		System.Console.WriteLine("Specify the Certificate to use");
		string cert = System.Console.ReadLine();
		System.Console.WriteLine("Enter Certificate Password");
		string pass = System.Console.ReadLine();
		
		DCSign dc = new DCSign(cert,pass);
		// Signing
		System.Console.WriteLine("Specify the file to Sign");
		string file = System.Console.ReadLine();
		if(file != "") { 
			dc.Sign(file); 
		} 
		// Verifying
		System.Console.WriteLine("Specify the signed file to verify.");
		string signedfile = System.Console.ReadLine();
		if(signedfile!=""){
			System.Console.WriteLine("Verifies: {0}",dc.Verify(signedfile));
		}
		// Extracting
		System.Console.WriteLine("Specify the file to extract.");
		string filetoextract = System.Console.ReadLine();
		System.Console.WriteLine("Specify the output file name");
		string outputfile = System.Console.ReadLine();
		if(filetoextract != "" && outputfile !=""){
			dc.Extract(filetoextract,outputfile);
		}
		
	}
}
using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;

namespace Neuralia.BouncyCastle.extra.security {
	public class DotNetUtilitiesExtensions {
		public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey)
		{
			return CreateRSAProvider(ToRSAParameters(privKey));
		}
		
		public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
		{
			RSAParameters rp = new RSAParameters();
			rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
			rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
			rp.P = privKey.P.ToByteArrayUnsigned();
			rp.Q = privKey.Q.ToByteArrayUnsigned();
			rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
			rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
			rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
			rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
			return rp;
		}
		
		private static byte[] ConvertRSAParametersField(BigInteger n, int size)
		{
			byte[] bs = n.ToByteArrayUnsigned();

			if (bs.Length == size)
				return bs;

			if (bs.Length > size)
				throw new ArgumentException("Specified size too small", "size");

			byte[] padded = new byte[size];
			Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
			return padded;
		}

		public static RSA LoadParameters(string file)
		{
			using(TextReader privateKeyTextReader = new StringReader(File.ReadAllText(file))) {
				AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair) new PemReader(privateKeyTextReader).ReadObject();

				RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);

				return ToRSA(privateKeyParams);
			}
		}
		
		private static RSA CreateRSAProvider(RSAParameters rp)
		{
			RSA rsa = RSA.Create();
            
			rsa.ImportParameters(rp);
             
			return rsa;
		}
	}
}
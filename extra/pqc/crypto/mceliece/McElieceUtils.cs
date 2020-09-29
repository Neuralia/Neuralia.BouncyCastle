using System;
using Neuralia.BouncyCastle.extra.crypto.digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	public class McElieceUtils {
		public const string SHA2_256 = "SHA2-256";
		public const string SHA2_512 = "SHA2-512";
		public const string SHA3_256 = "SHA3-256";
		public const string SHA3_512 = "SHA3-512";
		public const string BLAKE2_256 = "BLAKE2-256";
		public const string BLAKE2_512 = "BLAKE2-512";
		
		
		internal static IDigest getDigest(string digestName, Func<string, IDigest> digestGenerator) {
			return digestGenerator(digestName);
			
			// if(string.IsNullOrEmpty(digestName)) {
			// 	return new Sha256DotnetDigest();
			// }
			// if (digestName.Equals("SHA-1"))
			// {
			// 	return new Sha1Digest();
			// }
			// if (digestName.Equals("SHA-224"))
			// {
			// 	return new Sha224Digest();
			// }
			// if (digestName.Equals(SHA2_256))
			// {
			// 	return new Sha256DotnetDigest();
			// }
			// if (digestName.Equals("SHA-384"))
			// {
			// 	return new Sha384Digest();
			// }
			// if (digestName.Equals(SHA2_512))
			// {
			// 	return new Sha512DotnetDigest();
			// }
			// if (digestName.Equals(SHA3_256))
			// {
			// 	return new Sha3ExternalDigest(256);
			// }
			// if (digestName.Equals(SHA3_512))
			// {
			// 	return new Sha3ExternalDigest(512);
			// }
			// throw new System.ArgumentException("unrecognised digest algorithm: " + digestName);
		}
	}

}
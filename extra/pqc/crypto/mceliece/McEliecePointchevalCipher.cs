using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.crypto.digests;
using Neuralia.BouncyCastle.extra.pqc.crypto;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	/// <summary>
	/// This class implements the Pointcheval conversion of the McEliecePKCS.
	/// Pointcheval presents a generic technique to make a CCA2-secure cryptosystem
	/// from any partially trapdoor one-way function in the random oracle model. For
	/// details, see D. Engelbert, R. Overbeck, A. Schmidt, "A summary of the
	/// development of the McEliece Cryptosystem", technical report.
	/// </summary>
	public class McEliecePointchevalCipher : MessageEncryptor, IMcElieceCipher
	{


		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2.2";

		private IDigest messDigest;

		private SecureRandom sr;

		/// <summary>
		/// The McEliece main parameters
		/// </summary>
		private int n, k, t;

		
		internal McElieceCCA2KeyParameters key;
		private bool forEncryption;
		
		private Func<string, IDigest> digestGenerator;

		public McEliecePointchevalCipher(Func<string, IDigest> digestGenerator) {
			this.digestGenerator = digestGenerator;
		}

		public virtual void init(bool forEncryption, ICipherParameters param)
		{
			this.forEncryption = forEncryption;

			if (forEncryption)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.sr = rParam.Random;
					this.key = (McElieceCCA2PublicKeyParameters)rParam.Parameters;
					this.initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);

				}
				else
				{
					this.sr = new SecureRandom();
					this.key = (McElieceCCA2PublicKeyParameters)param;
					this.initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
				}
			}
			else
			{
				this.key = (McElieceCCA2PrivateKeyParameters)param;
				this.initCipherDecrypt((McElieceCCA2PrivateKeyParameters) this.key);
			}

		}

		/// <summary>
		/// Return the key size of the given key object.
		/// </summary>
		/// <param name="key"> the McElieceCCA2KeyParameters object </param>
		/// <returns> the key size of the given key object </returns>
		/// <exception cref="IllegalArgumentException"> if the key is invalid </exception>


		public virtual int getKeySize(McElieceCCA2KeyParameters key)
		{

			if (key is McElieceCCA2PublicKeyParameters)
			{
				return ((McElieceCCA2PublicKeyParameters)key).N;

			}
			if (key is McElieceCCA2PrivateKeyParameters)
			{
				return ((McElieceCCA2PrivateKeyParameters)key).N;
			}
			throw new ArgumentException("unsupported type");

		}


		protected internal virtual int decryptOutputSize(int inLen)
		{
			return 0;
		}

		protected internal virtual int encryptOutputSize(int inLen)
		{
			return 0;
		}


		private void initCipherEncrypt(McElieceCCA2PublicKeyParameters pubKey)
		{
			this.sr = this.sr != null ? this.sr : new SecureRandom();
			this.messDigest = Utils.getDigest(pubKey.Digest, this.digestGenerator);
			this.n = pubKey.N;
			this.k = pubKey.K;
			this.t = pubKey.T;
		}

		private void initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)
		{
			this.messDigest = Utils.getDigest(privKey.Digest, this.digestGenerator);
			this.n = privKey.N;
			this.k = privKey.K;
			this.t = privKey.T;
		}

		public virtual SafeArrayHandle messageEncrypt(SafeArrayHandle input)
		{
			if (!this.forEncryption)
			{
				throw new InvalidOperationException("cipher initialised for decryption");
			}

			int kDiv8 = this.k >> 3;

			// generate random r of length k div 8 bytes
			SafeArrayHandle r = ByteArray.Create(kDiv8);
			this.sr.NextBytes(r.ToExactByteArray());

			// generate random vector r' of length k bits
			GF2Vector rPrime = new GF2Vector(this.k, this.sr);

			// convert r' to byte array
			SafeArrayHandle rPrimeBytes = rPrime.Encoded;

			// compute (input||r)
			SafeArrayHandle mr = ByteUtils.concatenate(input, r);

			// compute H(input||r)
			this.messDigest.BlockUpdate(mr.ToExactByteArray(), 0, mr.Length);
			SafeArrayHandle hmr = ByteArray.Create(this.messDigest.GetDigestSize());
			
			byte[] result = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(result, 0);
			hmr.Entry.CopyFrom(result.AsSpan());


			// convert H(input||r) to error vector z
			GF2Vector z = Conversions.encode(this.n, this.t, hmr);

			// compute c1 = E(rPrime, z)
			SafeArrayHandle c1 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, rPrime, z).Encoded;

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(Utils.getDigest(Utils.SHA2_256, this.digestGenerator));

			// seed PRNG with r'
			sr0.AddSeedMaterial(rPrimeBytes.ToExactByteArray());

			// generate random c2
			SafeArrayHandle c2 = ByteArray.Create(input.Length + kDiv8);
			sr0.NextBytes(c2.ToExactByteArray());

			// XOR with input
			for (int i = 0; i < input.Length; i++)
			{
				c2[i] ^= input[i];
			}
			// XOR with r
			for (int i = 0; i < kDiv8; i++)
			{
				c2[input.Length + i] ^= r[i];
			}

			// return (c1||c2)
			return ByteUtils.concatenate(c1, c2);
		}



		public virtual SafeArrayHandle messageDecrypt(SafeArrayHandle input)
		{
			if (this.forEncryption)
			{
				throw new InvalidOperationException("cipher initialised for decryption");
			}

			int c1Len = (this.n + 7) >> 3;
			int c2Len = input.Length - c1Len;

			// split cipher text (c1||c2)
			var c1c2 = ByteUtils.split(input, c1Len);
			SafeArrayHandle c1 = c1c2[0];
			SafeArrayHandle c2 = c1c2[1];

			// decrypt c1 ...
			GF2Vector c1Vec = GF2Vector.OS2VP(this.n, c1);
			GF2Vector[] c1Dec = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, c1Vec);
			SafeArrayHandle rPrimeBytes = c1Dec[0].Encoded;
			// ... and obtain error vector z
			GF2Vector z = c1Dec[1];

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(Utils.getDigest(Utils.SHA2_256, this.digestGenerator));

			// seed PRNG with r'
			sr0.AddSeedMaterial(rPrimeBytes.ToExactByteArray());

			// generate random sequence
			SafeArrayHandle mrBytes = ByteArray.Create(c2Len);
			sr0.NextBytes(mrBytes.ToExactByteArray());

			// XOR with c2 to obtain (m||r)
			for (int i = 0; i < c2Len; i++)
			{
				mrBytes[i] ^= c2[i];
			}

			// compute H(m||r)
			this.messDigest.BlockUpdate(mrBytes.ToExactByteArray(), 0, mrBytes.Length);
			SafeArrayHandle hmr = ByteArray.Create(this.messDigest.GetDigestSize());
			
			byte[] result = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(result, 0);
			hmr.Entry.CopyFrom(result.AsSpan());

			// compute Conv(H(m||r))
			c1Vec = Conversions.encode(this.n, this.t, hmr);

			// check that Conv(H(m||r)) = z
			if (!c1Vec.Equals(z))
			{
				throw new InvalidCipherTextException("Bad Padding: Invalid ciphertext.");
			}

			// split (m||r) to obtain m
			int kDiv8 = this.k >> 3;
			var mr = ByteUtils.split(mrBytes, c2Len - kDiv8);

			// return plain text m
			return mr[0];
		}


	}

}
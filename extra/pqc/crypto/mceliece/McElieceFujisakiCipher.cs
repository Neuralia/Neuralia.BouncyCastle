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
	/// This class implements the Fujisaki/Okamoto conversion of the McEliecePKCS.
	/// Fujisaki and Okamoto propose hybrid encryption that merges a symmetric
	/// encryption scheme which is secure in the find-guess model with an asymmetric
	/// one-way encryption scheme which is sufficiently probabilistic to obtain a
	/// public key cryptosystem which is CCA2-secure. For details, see D. Engelbert,
	/// R. Overbeck, A. Schmidt, "A summary of the development of the McEliece
	/// Cryptosystem", technical report.
	/// </summary>
	public class McElieceFujisakiCipher : MessageEncryptor, IMcElieceCipher
	{
		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2.1";

		private const string DEFAULT_PRNG_NAME = "SHA1PRNG";

		private IDigest messDigest;

		private SecureRandom sr;

		/// <summary>
		/// The McEliece main parameters
		/// </summary>
		private int n, k, t;

		internal McElieceCCA2KeyParameters key;
		private bool forEncryption;

		private Func<string, IDigest> digestGenerator;

		public McElieceFujisakiCipher(Func<string, IDigest> digestGenerator) {
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
			this.t = privKey.T;
		}


		public virtual SafeArrayHandle messageEncrypt(SafeArrayHandle input)
		{
			if (!this.forEncryption)
			{
				throw new InvalidOperationException("cipher initialised for decryption");
			}

			// generate random vector r of length k bits
			GF2Vector r = new GF2Vector(this.k, this.sr);

			// convert r to byte array
			SafeArrayHandle rBytes = r.Encoded;

			// compute (r||input)
			SafeArrayHandle rm = ByteUtils.concatenate(rBytes, input);

			// compute H(r||input)
			this.messDigest.BlockUpdate(rm.ToExactByteArray(), 0, rm.Length);
			SafeArrayHandle hrm = ByteArray.Create(this.messDigest.GetDigestSize());
			byte[] result = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(result, 0);
			hrm.Entry.CopyFrom(result.AsSpan());
				
			// convert H(r||input) to error vector z
			GF2Vector z = Conversions.encode(this.n, this.t, hrm);

			// compute c1 = E(r, z)
			SafeArrayHandle c1 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, r, z).Encoded;

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(Utils.getDigest(Utils.SHA2_256, this.digestGenerator));

			// seed PRNG with r'
			sr0.AddSeedMaterial(rBytes.ToExactByteArray());

			// generate random c2
			SafeArrayHandle c2 = ByteArray.Create(input.Length);
			sr0.NextBytes(c2.ToExactByteArray());

			// XOR with input
			for (int i = 0; i < input.Length; i++)
			{
				c2[i] ^= input[i];
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

			// split ciphertext (c1||c2)
			var c1c2 = ByteUtils.split(input, c1Len);
			SafeArrayHandle c1 = c1c2[0];
			SafeArrayHandle c2 = c1c2[1];

			// decrypt c1 ...
			GF2Vector hrmVec = GF2Vector.OS2VP(this.n, c1);
			GF2Vector[] decC1 = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, hrmVec);
			SafeArrayHandle rBytes = decC1[0].Encoded;
			// ... and obtain error vector z
			GF2Vector z = decC1[1];

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(Utils.getDigest(Utils.SHA2_256, this.digestGenerator));

			// seed PRNG with r'
			sr0.AddSeedMaterial(rBytes.ToExactByteArray());

			// generate random sequence
			SafeArrayHandle mBytes = ByteArray.Create(c2Len);
			sr0.NextBytes(mBytes.ToExactByteArray());

			// XOR with c2 to obtain m
			for (int i = 0; i < c2Len; i++)
			{
				mBytes[i] ^= c2[i];
			}

			// compute H(r||m)
			SafeArrayHandle rmBytes = ByteUtils.concatenate(rBytes, mBytes);
			SafeArrayHandle hrm = ByteArray.Create(this.messDigest.GetDigestSize());
			this.messDigest.BlockUpdate(rmBytes.ToExactByteArray(), 0, rmBytes.Length);
			byte[] result = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(result, 0);
			hrm.Entry.CopyFrom(result.AsSpan());


			// compute Conv(H(r||m))
			hrmVec = Conversions.encode(this.n, this.t, hrm);

			// check that Conv(H(m||r)) = z
			if (!hrmVec.Equals(z))
			{
				throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
			}

			// return plaintext m
			return mBytes;
		}
	}

}
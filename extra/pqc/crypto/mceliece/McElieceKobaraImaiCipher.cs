using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.crypto.digests;
using Neuralia.BouncyCastle.extra.pqc.crypto;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;
using Neuralia.BouncyCastle.extra.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	/// <summary>
	/// This class implements the Kobara/Imai conversion of the McEliecePKCS. This is
	/// a conversion of the McEliecePKCS which is CCA2-secure. For details, see D.
	/// Engelbert, R. Overbeck, A. Schmidt, "A summary of the development of the
	/// McEliece Cryptosystem", technical report.
	/// </summary>
	public class McElieceKobaraImaiCipher : MessageEncryptor, IMcElieceCipher
	{

		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2.3";

		private const string DEFAULT_PRNG_NAME = "SHA1PRNG";

		/// <summary>
		/// A predetermined public constant.
		/// </summary>
		public static readonly SafeArrayHandle PUBLIC_CONSTANT = SafeArrayHandle.Wrap(System.Text.Encoding.UTF8.GetBytes("a predetermined public constant"));


		private IDigest messDigest;

		private SecureRandom sr;

		internal McElieceCCA2KeyParameters key;
		
		private Func<string, IDigest> digestGenerator;

		public McElieceKobaraImaiCipher(Func<string, IDigest> digestGenerator) {
			this.digestGenerator = digestGenerator;
		}

		/// <summary>
		/// The McEliece main parameters
		/// </summary>
		private int n, k, t;
		private bool forEncryption;


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
					this.sr = new BetterSecureRandom();
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
			this.messDigest = McElieceUtils.getDigest(pubKey.Digest, this.digestGenerator);
			this.n = pubKey.N;
			this.k = pubKey.K;
			this.t = pubKey.T;

		}

		private void initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)
		{
			this.messDigest = McElieceUtils.getDigest(privKey.Digest, this.digestGenerator);
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
			
			//TODO: we can do some serious SafeArrayHandle optimisation in these classes
			// there seems to be an issue here where the decrypted size is not the right size. so we store the size in the first 4 bytes.
			SafeArrayHandle newInput = SafeArrayHandle.Create(input.Length + sizeof(int));
			var bytes = BitConverter.GetBytes(input.Length);
			newInput[0] = bytes[0];
			newInput[1] = bytes[1];
			newInput[2] = bytes[2];
			newInput[3] = bytes[3];
			input.Entry.CopyTo(newInput.Entry, sizeof(int));
			input = newInput;

			int c2Len = this.messDigest.GetDigestSize();
			int c4Len = this.k >> 3;
			int c5Len = (IntegerFunctions.binomial(this.n, this.t).BitLength - 1) >> 3;


			int mLen = c4Len + c5Len - c2Len - PUBLIC_CONSTANT.Length;
			if (input.Length > mLen)
			{
				mLen = input.Length;
			}

			int c1Len = mLen + PUBLIC_CONSTANT.Length;
			int c6Len = c1Len + c2Len - c4Len - c5Len;

			// compute (m||const)
			SafeArrayHandle mConst = SafeArrayHandle.Create(c1Len);
			input.Entry.CopyTo(mConst.Entry);
			PUBLIC_CONSTANT.Entry.CopyTo(mConst.Entry, 0, mLen, PUBLIC_CONSTANT.Length);

			// generate random r of length c2Len bytes
			SafeArrayHandle r = SafeArrayHandle.Create(c2Len);
			this.sr.NextBytes(r.ToExactByteArray());

			// get PRNG object
					// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(McElieceUtils.getDigest(McElieceUtils.SHA2_256, this.digestGenerator));

			// seed PRNG with r'
			sr0.AddSeedMaterial(r.ToExactByteArray());

			// generate random sequence ...
			SafeArrayHandle c1 = SafeArrayHandle.Create(c1Len);
			sr0.NextBytes(c1.ToExactByteArray());

			// ... and XOR with (m||const) to obtain c1
			for (int i = c1Len - 1; i >= 0; i--)
			{
				c1[i] ^= mConst[i];
			}

			// compute H(c1) ...
			SafeArrayHandle c2 = SafeArrayHandle.Create(this.messDigest.GetDigestSize());
			this.messDigest.BlockUpdate(c1.ToExactByteArray(), 0, c1.Length);
			
			byte[] result = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(result, 0);
			c2.Entry.CopyFrom(result.AsSpan());


			// ... and XOR with r
			for (int i = c2Len - 1; i >= 0; i--)
			{
				c2[i] ^= r[i];
			}

			// compute (c2||c1)
			using SafeArrayHandle c2c1 = ByteUtils.concatenate(c2, c1);

			// split (c2||c1) into (c6||c5||c4), where c4Len is k/8 bytes, c5Len is
			// floor[log(n|t)]/8 bytes, and c6Len is c1Len+c2Len-c4Len-c5Len (may be
			// 0).
			SafeArrayHandle c6 = SafeArrayHandle.Create(0);
			if (c6Len > 0)
			{
				c6.Dispose();
				c6 = SafeArrayHandle.Create(c6Len);
				c2c1.Entry.CopyTo(c6.Entry, 0, 0, c6Len);
			}

			using SafeArrayHandle c5 = SafeArrayHandle.Create(c5Len);
			c2c1.Entry.CopyTo(c5.Entry, c6Len, 0, c5Len);

			using SafeArrayHandle c4 = SafeArrayHandle.Create(c4Len);
			c2c1.Entry.CopyTo(c4.Entry, c6Len + c5Len, 0, c4Len);

			// convert c4 to vector over GF(2)
			GF2Vector c4Vec = GF2Vector.OS2VP(this.k, c4);

			// convert c5 to error vector z
			GF2Vector z = Conversions.encode(this.n, this.t, c5);

			// compute encC4 = E(c4, z)
			SafeArrayHandle encC4 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, c4Vec, z).Encoded;

			// if c6Len > 0
			if (c6Len > 0)
			{
				// return (c6||e.DatancC4)
				return ByteUtils.concatenate(c6, encC4);
			}
			// else, return encC4
			return encC4;
		}




		public virtual SafeArrayHandle messageDecrypt(SafeArrayHandle input)
		{
			if (this.forEncryption)
			{
				throw new InvalidOperationException("cipher initialised for decryption");
			}
			
			int nDiv8 = this.n >> 3;

			if (input.Length < nDiv8)
			{
				throw new InvalidCipherTextException("Bad Padding: Ciphertext too short.");
			}

			int c2Len = this.messDigest.GetDigestSize();
			int c4Len = this.k >> 3;
			int c6Len = input.Length - nDiv8;

			// split cipher text (c6||encC4), where c6 may be empty
			SafeArrayHandle c6, encC4;
			if (c6Len > 0)
			{
				var c6EncC4 = ByteUtils.split(input, c6Len);
				c6 = (SafeArrayHandle)c6EncC4[0];
				encC4 = (SafeArrayHandle)c6EncC4[1];
			}
			else
			{
				c6 = SafeArrayHandle.Create(0);
				encC4 = input;
			}

			// convert encC4 into vector over GF(2)
			GF2Vector encC4Vec = GF2Vector.OS2VP(this.n, encC4);

			// decrypt encC4Vec to obtain c4 and error vector z
			GF2Vector[] c4z = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, encC4Vec);
			SafeArrayHandle c4 = c4z[0].Encoded;
			GF2Vector z = c4z[1];

			// if length of c4 is greater than c4Len (because of padding) ...
			if (c4.Length > c4Len)
			{
				// ... truncate the padding bytes
				c4 = ByteUtils.subArray(c4, 0, c4Len);
			}

			// compute c5 = Conv^-1(z)
			SafeArrayHandle c5 = Conversions.decode(this.n, this.t, z);

			// compute (c6||c5||c4)
			SafeArrayHandle c6c5c4 = ByteUtils.concatenate(c6, c5);
			c6c5c4 = ByteUtils.concatenate(c6c5c4, c4);

			// split (c6||c5||c4) into (c2||c1), where c2Len = mdLen and c1Len =
			// input.length-c2Len bytes.
			int c1Len = c6c5c4.Length - c2Len;
			var c2c1 = ByteUtils.split(c6c5c4, c2Len);
			SafeArrayHandle c2 = (SafeArrayHandle)c2c1[0];
			SafeArrayHandle c1 = (SafeArrayHandle)c2c1[1];

			// compute H(c1) ...
			using SafeArrayHandle rPrime = SafeArrayHandle.Create(this.messDigest.GetDigestSize());
			this.messDigest.BlockUpdate(c1.ToExactByteArray(), 0, c1.Length);
			
			byte[] result = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(result, 0);
			rPrime.Entry.CopyFrom(result.AsSpan());

			// ... and XOR with c2 to obtain r'
			for (int i = c2Len - 1; i >= 0; i--)
			{
				rPrime[i] ^= c2[i];
			}

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(McElieceUtils.getDigest(McElieceUtils.SHA2_256, this.digestGenerator));

			// seed PRNG with r'
			sr0.AddSeedMaterial(rPrime.ToExactByteArray());

			// generate random sequence R(r') ...
			SafeArrayHandle mConstPrime = SafeArrayHandle.Create(c1Len);
			sr0.NextBytes(mConstPrime.ToExactByteArray());

			// ... and XOR with c1 to obtain (m||const')
			for (int i = c1Len - 1; i >= 0; i--)
			{
				mConstPrime[i] ^= c1[i];
			}

			if (mConstPrime.Length < c1Len)
			{
				throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
			}

			var temp = ByteUtils.split(mConstPrime, c1Len - PUBLIC_CONSTANT.Length);
			SafeArrayHandle mr = (SafeArrayHandle)temp[0];
			SafeArrayHandle constPrime = (SafeArrayHandle)temp[1];

			if (!ByteUtils.Equals(constPrime, PUBLIC_CONSTANT))
			{
				throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
			}

			// there seems to be an issue here where the decrypted size is not the right size. so we store the size in the first 4 bytes.
			
			byte[] sizeBytes = new byte[sizeof(int)];
			sizeBytes[0] = mr[0];
			sizeBytes[1] = mr[1];
			sizeBytes[2] = mr[2];
			sizeBytes[3] = mr[3];

			int length = BitConverter.ToInt32(sizeBytes, 0);
			
			SafeArrayHandle newInput = SafeArrayHandle.Create(length);
			mr.Entry.CopyTo(newInput.Entry, sizeof(int), 0, length);

			return newInput;
		}
	}

}
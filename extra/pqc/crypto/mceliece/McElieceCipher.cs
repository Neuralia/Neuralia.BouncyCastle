using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.crypto;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	/// <summary>
	/// This class implements the McEliece Public Key cryptosystem (McEliecePKCS). It
	/// was first described in R.J. McEliece, "A public key cryptosystem based on
	/// algebraic coding theory", DSN progress report, 42-44:114-116, 1978. The
	/// McEliecePKCS is the first cryptosystem which is based on error correcting
	/// codes. The trapdoor for the McEliece cryptosystem using Goppa codes is the
	/// knowledge of the Goppa polynomial used to generate the code.
	/// </summary>
	public class McElieceCipher : MessageEncryptor, IMcElieceCipher
	{

		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.1";


		// the source of randomness
		private SecureRandom sr;

		// the McEliece main parameters
		private int n, k, t;

		// The maximum number of bytes the cipher can decrypt
		public int maxPlainTextSize;

		// The maximum number of bytes the cipher can encrypt
		public int cipherTextSize;

		private McElieceKeyParameters key;
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
					this.key = (McEliecePublicKeyParameters)rParam.Parameters;
					this.initCipherEncrypt((McEliecePublicKeyParameters) this.key);

				}
				else
				{
					this.sr = new SecureRandom();
					this.key = (McEliecePublicKeyParameters)param;
					this.initCipherEncrypt((McEliecePublicKeyParameters) this.key);
				}
			}
			else
			{
				this.key = (McEliecePrivateKeyParameters)param;
				this.initCipherDecrypt((McEliecePrivateKeyParameters) this.key);
			}

		}

		/// <summary>
		/// Return the key size of the given key object.
		/// </summary>
		/// <param name="key"> the McElieceKeyParameters object </param>
		/// <returns> the keysize of the given key object </returns>

		public virtual int getKeySize(McElieceKeyParameters key)
		{

			if (key is McEliecePublicKeyParameters)
			{
				return ((McEliecePublicKeyParameters)key).N;

			}
			if (key is McEliecePrivateKeyParameters)
			{
				return ((McEliecePrivateKeyParameters)key).N;
			}
			throw new ArgumentException("unsupported type");

		}


		private void initCipherEncrypt(McEliecePublicKeyParameters pubKey)
		{
			this.sr = this.sr != null ? this.sr : new SecureRandom();
			this.n = pubKey.N;
			this.k = pubKey.K;
			this.t = pubKey.T;
			this.cipherTextSize = this.n >> 3;
			this.maxPlainTextSize = (this.k >> 3);
		}


		private void initCipherDecrypt(McEliecePrivateKeyParameters privKey)
		{
			this.n = privKey.N;
			this.k = privKey.K;

			this.maxPlainTextSize = (this.k >> 3);
			this.cipherTextSize = this.n >> 3;
		}

		/// <summary>
		/// Encrypt a plain text.
		/// </summary>
		/// <param name="input"> the plain text </param>
		/// <returns> the cipher text </returns>
		public virtual IByteArray messageEncrypt(IByteArray input)
		{
			if (!this.forEncryption)
			{
				throw new InvalidOperationException("cipher initialised for decryption");
			}
			GF2Vector m = this.computeMessageRepresentative(input);
			GF2Vector z = new GF2Vector(this.n, this.t, this.sr);

			GF2Matrix g = ((McEliecePublicKeyParameters) this.key).G;
			Vector mG = g.leftMultiply(m);
			GF2Vector mGZ = (GF2Vector)mG.add(z);

			return mGZ.Encoded;
		}

		private GF2Vector computeMessageRepresentative(IByteArray input)
		{
			IByteArray data = new ByteArray(this.maxPlainTextSize + ((this.k & 0x07) != 0 ? 1 : 0));
			input.CopyTo(data, 0, 0, input.Length);
			data[input.Length] = 0x01;
			return GF2Vector.OS2VP(this.k, data);
		}

		/// <summary>
		/// Decrypt a cipher text.
		/// </summary>
		/// <param name="input"> the cipher text </param>
		/// <returns> the plain text </returns>
		/// <exception cref="InvalidCipherTextException"> if the cipher text is invalid. </exception>


		public virtual IByteArray messageDecrypt(IByteArray input)
		{
			if (this.forEncryption)
			{
				throw new InvalidOperationException("cipher initialised for decryption");
			}

			GF2Vector vec = GF2Vector.OS2VP(this.n, input);
			McEliecePrivateKeyParameters privKey = (McEliecePrivateKeyParameters) this.key;
			GF2mField field = privKey.Field;
			PolynomialGF2mSmallM gp = privKey.GoppaPoly;
			GF2Matrix sInv = privKey.SInv;
			Permutation p1 = privKey.P1;
			Permutation p2 = privKey.P2;
			GF2Matrix h = privKey.H;
			PolynomialGF2mSmallM[] qInv = privKey.QInv;

			// compute permutation P = P1 * P2
			Permutation p = p1.rightMultiply(p2);

			// compute P^-1
			Permutation pInv = p.computeInverse();

			// compute c P^-1
			GF2Vector cPInv = (GF2Vector)vec.multiply(pInv);

			// compute syndrome of c P^-1
			GF2Vector syndrome = (GF2Vector)h.rightMultiply(cPInv);

			// decode syndrome
			GF2Vector z = GoppaCode.syndromeDecode(syndrome, field, gp, qInv);
			GF2Vector mSG = (GF2Vector)cPInv.add(z);

			// multiply codeword with P1 and error vector with P
			mSG = (GF2Vector)mSG.multiply(p1);
			z = (GF2Vector)z.multiply(p);

			// extract mS (last k columns of mSG)
			GF2Vector mS = mSG.extractRightVector(this.k);

			// compute plaintext vector
			GF2Vector mVec = (GF2Vector)sInv.leftMultiply(mS);

			// compute and return plaintext
			return this.computeMessage(mVec);
		}

		private IByteArray computeMessage(GF2Vector mr)
		{
			IByteArray mrBytes = mr.Encoded;
			// find first non-zero byte
			int index;
			for (index = mrBytes.Length - 1; index >= 0 && mrBytes[index] == 0; index--)
			{
				;
			}

			// check if padding byte is valid
			if (index < 0 || mrBytes[index] != 0x01)
			{
				throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
			}

			// extract and return message
			IByteArray mBytes = new ByteArray(index);
			mrBytes.CopyTo(mBytes, 0, 0, index);
			return mBytes;
		}


	}

}
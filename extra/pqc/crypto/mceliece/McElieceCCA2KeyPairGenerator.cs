using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	/// <summary>
	/// This class implements key pair generation of the McEliece Public Key
	/// Cryptosystem (McEliecePKC).
	/// </summary>
	public class McElieceCCA2KeyPairGenerator 
	{


		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

		private McElieceCCA2KeyGenerationParameters mcElieceCCA2Params;

		// the extension degree of the finite field GF(2^m)
		private int m;

		// the length of the code
		private int n;

		// the error correction capability
		private int t;

		// the field polynomial
		private int fieldPoly;

		// the source of randomness
		private SecureRandom random;

		// flag indicating whether the key pair generator has been initialized
		private bool initialized = false;

		/// <summary>
		/// Default initialization of the key pair generator.
		/// </summary>
		private void initializeDefault()
		{
			McElieceCCA2KeyGenerationParameters mcCCA2Params = new McElieceCCA2KeyGenerationParameters(new SecureRandom(), new McElieceCCA2Parameters());
			this.init(mcCCA2Params);
		}

		// TODO
		public virtual void init(KeyGenerationParameters param)
		{
			this.mcElieceCCA2Params = (McElieceCCA2KeyGenerationParameters)param;

			// set source of randomness
			this.random = param.Random;

			this.m = this.mcElieceCCA2Params.Parameters.M;
			this.n = this.mcElieceCCA2Params.Parameters.N;
			this.t = this.mcElieceCCA2Params.Parameters.T;
			this.fieldPoly = this.mcElieceCCA2Params.Parameters.FieldPoly;
			this.initialized = true;
		}


		public virtual McElieceCCA2AsymmetricCipherKeyPair generateKeyPair()
		{

			if (!this.initialized)
			{
				this.initializeDefault();
			}

			// finite field GF(2^m)
			GF2mField field = new GF2mField(this.m, this.fieldPoly);

			// irreducible Goppa polynomial
			PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, this.t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, this.random);

			// generate canonical check matrix
			GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);

			// compute short systematic form of check matrix
			GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(h, this.random);
			GF2Matrix shortH = mmp.SecondMatrix;
			Permutation p = mmp.Permutation;

			// compute short systematic form of generator matrix
			GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

			// obtain number of rows of G (= dimension of the code)
			int k = shortG.NumRows;

			// generate keys
			McElieceCCA2PublicKeyParameters pubKey = new McElieceCCA2PublicKeyParameters(this.n, this.t, shortG, this.mcElieceCCA2Params.Parameters.Digest);
			McElieceCCA2PrivateKeyParameters privKey = new McElieceCCA2PrivateKeyParameters(this.n, k, field, gp, p, this.mcElieceCCA2Params.Parameters.Digest);

			// return key pair
			return new McElieceCCA2AsymmetricCipherKeyPair(pubKey, privKey);
		}
	}

}
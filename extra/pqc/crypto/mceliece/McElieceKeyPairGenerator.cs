using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{



	/// <summary>
	/// This class implements key pair generation of the McEliece Public Key
	/// Cryptosystem (McEliecePKC).
	/// </summary>
	public class McElieceKeyPairGenerator 
	{


		public McElieceKeyPairGenerator()
		{

		}


		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		private const string OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

		private McElieceKeyGenerationParameters mcElieceParams;

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
			McElieceKeyGenerationParameters mcParams = new McElieceKeyGenerationParameters(new SecureRandom(), new McElieceParameters());
			this.initialize(mcParams);
		}

		private void initialize(KeyGenerationParameters param)
		{
			this.mcElieceParams = (McElieceKeyGenerationParameters)param;

			// set source of randomness
			this.random = param.Random;
			if (this.random == null)
			{
				this.random = new SecureRandom();
			}

			this.m = this.mcElieceParams.Parameters.M;
			this.n = this.mcElieceParams.Parameters.N;
			this.t = this.mcElieceParams.Parameters.T;
			this.fieldPoly = this.mcElieceParams.Parameters.FieldPoly;
			this.initialized = true;
		}


		private AsymmetricCipherKeyPair genKeyPair()
		{

			if (!this.initialized)
			{
				this.initializeDefault();
			}

			// finite field GF(2^m)
			GF2mField field = new GF2mField(this.m, this.fieldPoly);

			// irreducible Goppa polynomial
			PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, this.t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, this.random);
			PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

			// matrix used to compute square roots in (GF(2^m))^t
			PolynomialGF2mSmallM[] sqRootMatrix = ring.SquareRootMatrix;

			// generate canonical check matrix
			GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);

			// compute short systematic form of check matrix
			GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(h, this.random);
			GF2Matrix shortH = mmp.SecondMatrix;
			Permutation p1 = mmp.Permutation;

			// compute short systematic form of generator matrix
			GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

			// extend to full systematic form
			GF2Matrix gPrime = shortG.extendLeftCompactForm();

			// obtain number of rows of G (= dimension of the code)
			int k = shortG.NumRows;

			// generate random invertible (k x k)-matrix S and its inverse S^-1
			GF2Matrix[] matrixSandInverse = GF2Matrix.createRandomRegularMatrixAndItsInverse(k, this.random);

			// generate random permutation P2
			Permutation p2 = new Permutation(this.n, this.random);

			// compute public matrix G=S*G'*P2
			GF2Matrix g = (GF2Matrix)matrixSandInverse[0].rightMultiply(gPrime);
			g = (GF2Matrix)g.rightMultiply(p2);


			// generate keys
			McEliecePublicKeyParameters pubKey = new McEliecePublicKeyParameters(this.n, this.t, g);
			McEliecePrivateKeyParameters privKey = new McEliecePrivateKeyParameters(this.n, k, field, gp, p1, p2, matrixSandInverse[1]);

			// return key pair
			return new AsymmetricCipherKeyPair(pubKey, privKey);
		}

		public virtual void init(KeyGenerationParameters param)
		{
			this.initialize(param);
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			return this.genKeyPair();
		}

	}

}
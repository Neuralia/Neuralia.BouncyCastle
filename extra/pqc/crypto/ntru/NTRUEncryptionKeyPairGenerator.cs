
using Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.util;
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	/// <summary>
	///     Generates key pairs.
	///     <br>
	///         The parameter p is hardcoded to 3.
	/// </summary>
	public class NTRUEncryptionKeyPairGenerator {
		private NTRUEncryptionKeyGenerationParameters @params;

		public NTRUEncryptionKeyPairGenerator() {

		}

		public NTRUEncryptionKeyPairGenerator(KeyGenerationParameters param) {
			this.Init(param);
		}

		/// <summary>
		///     Constructs a new instance with a set of encryption parameters.
		/// </summary>
		/// <param name="param"> encryption parameters </param>
		public virtual void Init(KeyGenerationParameters param) {
			this.@params = (NTRUEncryptionKeyGenerationParameters) param;
		}

		/// <summary>
		///     Generates a new encryption key pair.
		/// </summary>
		/// <returns> a key pair </returns>
		public virtual NTRUAsymmetricCipherKeyPair GenerateKeyPair() {
			int  N      = this.@params.N;
			int  q      = this.@params.q;
			int  df     = this.@params.df;
			int  df1    = this.@params.df1;
			int  df2    = this.@params.df2;
			int  df3    = this.@params.df3;
			int  dg     = this.@params.dg;
			bool fastFp = this.@params.fastFp;
			bool sparse = this.@params.sparse;

			IPolynomial       t;
			IntegerPolynomial fq;
			IntegerPolynomial fp = null;

			// choose a random f that is invertible mod 3 and q
			while(true) {
				IntegerPolynomial f;

				// choose random t, calculate f and fp
				if(fastFp) {
					// if fastFp=true, f is always invertible mod 3
					if(this.@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE) {
						t = Util.generateRandomTernary(N, df, df, sparse, this.@params.Random);
					} else {
						t = ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3, this.@params.Random);
					}

					f = t.toIntegerPolynomial();
					f.mult(3);
					f.coeffs[0] += 1;
				} else {
					if(this.@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE) {
						t = Util.generateRandomTernary(N, df, df - 1, sparse, this.@params.Random);
					} else {
						t = ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3 - 1, this.@params.Random);
					}

					f  = t.toIntegerPolynomial();
					fp = f.invertF3();

					if(fp == null) {
						continue;
					}
				}

				fq = f.invertFq(q);

				if(fq == null) {
					continue;
				}

				break;
			}

			// if fastFp=true, fp=1
			if(fastFp) {
				fp           = new IntegerPolynomial(N);
				fp.coeffs[0] = 1;
			}

			// choose a random g that is invertible mod q
			DenseTernaryPolynomial g;

			while(true) {
				g = DenseTernaryPolynomial.generateRandom(N, dg, dg - 1, this.@params.Random);

				if(g.invertFq(q) != null) {
					break;
				}
			}

			IntegerPolynomial h = g.mult(fq, q);
			h.mult3(q);
			h.ensurePositive(q);
			g.clear();
			fq.clear();

			NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(h, t, fp, this.@params.EncryptionParameters);
			NTRUEncryptionPublicKeyParameters  pub  = new NTRUEncryptionPublicKeyParameters(h, this.@params.EncryptionParameters);

			return new NTRUAsymmetricCipherKeyPair(pub, priv);
		}
	}
}
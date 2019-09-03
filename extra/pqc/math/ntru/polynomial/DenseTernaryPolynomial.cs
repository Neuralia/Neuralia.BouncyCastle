using System;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.util;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A <code>TernaryPolynomial</code> with a "high" number of nonzero coefficients.
	/// </summary>
	public class DenseTernaryPolynomial : IntegerPolynomial, TernaryPolynomial {

		/// <summary>
		///     Constructs a new <code>DenseTernaryPolynomial</code> with <code>N</code> coefficients.
		/// </summary>
		/// <param name="N"> the number of coefficients </param>
		internal DenseTernaryPolynomial(int N) : base(N) {
			this.checkTernarity();
		}

		/// <summary>
		///     Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		///     independent of each other.
		/// </summary>
		/// <param name="intPoly"> the original polynomial </param>
		public DenseTernaryPolynomial(IntegerPolynomial intPoly) : this(intPoly.coeffs) {
		}

		/// <summary>
		///     Constructs a new <code>DenseTernaryPolynomial</code> with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		public DenseTernaryPolynomial(int[] coeffs) : base(coeffs) {
			this.checkTernarity();
		}

		public override IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
			// even on 32-bit systems, LongPolynomial5 multiplies faster than IntegerPolynomial
			if(modulus == 2048) {
				IntegerPolynomial poly2Pos = poly2.clone();
				poly2Pos.modPositive(2048);
				LongPolynomial5 poly5 = new LongPolynomial5(poly2Pos);

				return poly5.mult(this).toIntegerPolynomial();
			}

			return base.mult(poly2, modulus);
		}

		public virtual int[] Ones {
			get {
				int   N       = this.coeffs.Length;
				int[] ones    = new int[N];
				int   onesIdx = 0;

				for(int i = 0; i < N; i++) {
					int c = this.coeffs[i];

					if(c == 1) {
						ones[onesIdx++] = i;
					}
				}

				return Arrays.CopyOf(ones, onesIdx);
			}
		}

		public virtual int[] NegOnes {
			get {
				int   N          = this.coeffs.Length;
				int[] negOnes    = new int[N];
				int   negOnesIdx = 0;

				for(int i = 0; i < N; i++) {
					int c = this.coeffs[i];

					if(c == -1) {
						negOnes[negOnesIdx++] = i;
					}
				}

				return Arrays.CopyOf(negOnes, negOnesIdx);
			}
		}

		public virtual int size() {
			return this.coeffs.Length;
		}

		private void checkTernarity() {
			for(int i = 0; i != this.coeffs.Length; i++) {
				int c = this.coeffs[i];

				if((c < -1) || (c > 1)) {
					throw new InvalidOperationException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
				}
			}
		}

		/// <summary>
		///     Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		///     <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N">          number of coefficients </param>
		/// <param name="numOnes">    number of 1's </param>
		/// <param name="numNegOnes"> number of -1's </param>
		public static DenseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes, SecureRandom random) {
			int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes, random);

			return new DenseTernaryPolynomial(coeffs);
		}

		/// <summary>
		///     Generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
		/// </summary>
		/// <param name="N"> number of coefficients </param>
		public static DenseTernaryPolynomial generateRandom(int N, SecureRandom random) {
			DenseTernaryPolynomial poly = new DenseTernaryPolynomial(N);

			for(int i = 0; i < N; i++) {
				poly.coeffs[i] = random.Next(3) - 1;
			}

			return poly;
		}
	}

}
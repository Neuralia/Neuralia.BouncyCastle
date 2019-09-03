using System;
using System.Collections.Generic;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.util;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A polynomial with <seealso cref="BigInteger" /> coefficients.
	///     <br>
	///         Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
	///         not but return the result as a new polynomial.
	/// </summary>
	public class BigIntPolynomial {
		private static readonly double LOG_10_2 = Math.Log10(2);

		internal BigInteger[] coeffs;

		/// <summary>
		///     Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
		/// </summary>
		/// <param name="N"> the number of coefficients </param>
		internal BigIntPolynomial(int N) {
			this.coeffs = new BigInteger[N];

			for(int i = 0; i < N; i++) {
				this.coeffs[i] = Constants.BIGINT_ZERO;
			}
		}

		/// <summary>
		///     Constructs a new polynomial with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		internal BigIntPolynomial(BigInteger[] coeffs) {
			this.coeffs = coeffs;
		}

		/// <summary>
		///     Constructs a <code>BigIntPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		///     independent of each other.
		/// </summary>
		/// <param name="p"> the original polynomial </param>
		public BigIntPolynomial(IntegerPolynomial p) {
			this.coeffs = new BigInteger[p.coeffs.Length];

			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] = BigInteger.ValueOf(p.coeffs[i]);
			}
		}

		/// <summary>
		///     Returns the base10 length of the largest coefficient.
		/// </summary>
		/// <returns> length of the longest coefficient </returns>
		public virtual int MaxCoeffLength => (int) (this.maxCoeffAbs().BitLength * LOG_10_2) + 1;

		public virtual BigInteger[] Coeffs => ArraysExtensions.Clone(this.coeffs);

		/// <summary>
		///     Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		///     <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N">          number of coefficients </param>
		/// <param name="numOnes">    number of 1's </param>
		/// <param name="numNegOnes"> number of -1's </param>
		/// <returns> a random polynomial. </returns>
		internal static BigIntPolynomial generateRandomSmall(int N, int numOnes, int numNegOnes) {
			List<BigInteger> coeffs = new List<BigInteger>();

			for(int i = 0; i < numOnes; i++) {
				coeffs.Add(Constants.BIGINT_ONE);
			}

			for(int i = 0; i < numNegOnes; i++) {
				coeffs.Add(BigInteger.ValueOf(-1));
			}

			while(coeffs.Count < N) {
				coeffs.Add(Constants.BIGINT_ZERO);
			}

			coeffs.Shuffle(new SecureRandom());

			BigIntPolynomial poly = new BigIntPolynomial(N);

			for(int i = 0; i < coeffs.Count; i++) {
				poly.coeffs[i] = coeffs[i];
			}

			return poly;
		}

		/// <summary>
		///     Multiplies the polynomial by another, taking the indices mod N. Does not
		///     change this polynomial but returns the result as a new polynomial.
		///     <br>
		///         Both polynomials must have the same number of coefficients.
		/// </summary>
		/// <param name="poly2"> the polynomial to multiply by </param>
		/// <returns> a new polynomial </returns>
		public virtual BigIntPolynomial mult(BigIntPolynomial poly2) {
			int N = this.coeffs.Length;

			if(poly2.coeffs.Length != N) {
				throw new ArgumentException("Number of coefficients must be the same");
			}

			BigIntPolynomial c = this.multRecursive(poly2);

			if(c.coeffs.Length > N) {
				for(int k = N; k < c.coeffs.Length; k++) {
					c.coeffs[k - N] = c.coeffs[k - N] + c.coeffs[k];
				}

				c.coeffs = ArraysExtensions.CopyOf(c.coeffs, N);
			}

			return c;
		}

		/// <summary>
		///     Karazuba multiplication
		/// </summary>
		private BigIntPolynomial multRecursive(BigIntPolynomial poly2) {
			BigInteger[] a = this.coeffs;
			BigInteger[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;

			if(n <= 1) {
				BigInteger[] c = ArraysExtensions.Clone(this.coeffs);

				for(int i = 0; i < this.coeffs.Length; i++) {
					c[i] = c[i] * poly2.coeffs[0];
				}

				return new BigIntPolynomial(c);
			} else {
				int n1 = n / 2;

				BigIntPolynomial a1 = new BigIntPolynomial(ArraysExtensions.CopyOf(a, n1));
				BigIntPolynomial a2 = new BigIntPolynomial(ArraysExtensions.CopyOfRange(a, n1, n));
				BigIntPolynomial b1 = new BigIntPolynomial(ArraysExtensions.CopyOf(b, n1));
				BigIntPolynomial b2 = new BigIntPolynomial(ArraysExtensions.CopyOfRange(b, n1, n));

				BigIntPolynomial A = a1.clone();
				A.add(a2);
				BigIntPolynomial B = b1.clone();
				B.add(b2);

				BigIntPolynomial c1 = a1.multRecursive(b1);
				BigIntPolynomial c2 = a2.multRecursive(b2);
				BigIntPolynomial c3 = A.multRecursive(B);
				c3.sub(c1);
				c3.sub(c2);

				BigIntPolynomial c = new BigIntPolynomial((2 * n) - 1);

				for(int i = 0; i < c1.coeffs.Length; i++) {
					c.coeffs[i] = c1.coeffs[i];
				}

				for(int i = 0; i < c3.coeffs.Length; i++) {
					c.coeffs[n1 + i] = c.coeffs[n1 + i] + c3.coeffs[i];
				}

				for(int i = 0; i < c2.coeffs.Length; i++) {
					c.coeffs[(2 * n1) + i] = c.coeffs[(2 * n1) + i] + c2.coeffs[i];
				}

				return c;
			}
		}

		/// <summary>
		///     Adds another polynomial which can have a different number of coefficients,
		///     and takes the coefficient values mod <code>modulus</code>.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		internal virtual void add(BigIntPolynomial b, BigInteger modulus) {
			this.add(b);
			this.mod(modulus);
		}

		/// <summary>
		///     Adds another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void add(BigIntPolynomial b) {
			if(b.coeffs.Length > this.coeffs.Length) {
				int N = this.coeffs.Length;
				this.coeffs = ArraysExtensions.CopyOf(this.coeffs, b.coeffs.Length);

				for(int i = N; i < this.coeffs.Length; i++) {
					this.coeffs[i] = Constants.BIGINT_ZERO;
				}
			}

			for(int i = 0; i < b.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] + b.coeffs[i];
			}
		}

		/// <summary>
		///     Subtracts another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void sub(BigIntPolynomial b) {
			if(b.coeffs.Length > this.coeffs.Length) {
				int N = this.coeffs.Length;
				this.coeffs = ArraysExtensions.CopyOf(this.coeffs, b.coeffs.Length);

				for(int i = N; i < this.coeffs.Length; i++) {
					this.coeffs[i] = Constants.BIGINT_ZERO;
				}
			}

			for(int i = 0; i < b.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] - b.coeffs[i];
			}
		}

		/// <summary>
		///     Multiplies each coefficient by a <code>BigInteger</code>. Does not return a new polynomial but modifies this
		///     polynomial.
		/// </summary>
		/// <param name="factor"> </param>
		public virtual void mult(BigInteger factor) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] * factor;
			}
		}

		/// <summary>
		///     Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="factor"> </param>
		internal virtual void mult(int factor) {
			this.mult(BigInteger.ValueOf(factor));
		}

		/// <summary>
		///     Divides each coefficient by a <code>BigInteger</code> and rounds the result to the nearest whole number.
		///     <br>
		///         Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="divisor"> the number to divide by </param>
		public virtual void div(BigInteger divisor) {
			BigInteger d = divisor + Constants.BIGINT_ONE.Divide(BigInteger.ValueOf(2));

			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i].CompareTo(Constants.BIGINT_ZERO) > 0 ? this.coeffs[i] + d : this.coeffs[i] + -d;
				this.coeffs[i] = this.coeffs[i] / divisor;
			}
		}

		/// <summary>
		///     Divides each coefficient by a <code>BigDecimal</code> and rounds the result to <code>decimalPlaces</code> places.
		/// </summary>
		/// <param name="divisor">       the number to divide by </param>
		/// <param name="decimalPlaces"> the number of fractional digits to round the result to </param>
		/// <returns> a new <code>BigDecimalPolynomial</code> </returns>
		public virtual BigDecimalPolynomial div(BigDecimal divisor, int decimalPlaces) {
			BigInteger max         = this.maxCoeffAbs();
			int        coeffLength = (int) (max.BitLength * LOG_10_2) + 1;

			// factor = 1/divisor
			BigDecimal factor = BigDecimal.One.Divide(divisor, coeffLength + decimalPlaces + 1, RoundingModes.HalfEven);

			// multiply each coefficient by factor
			BigDecimalPolynomial p = new BigDecimalPolynomial(this.coeffs.Length);

			for(int i = 0; i < this.coeffs.Length; i++) {
				// multiply, then truncate after decimalPlaces so subsequent operations aren't slowed down
				p.coeffs[i] = new BigDecimal(this.coeffs[i]).Multiply(factor).SetScale(decimalPlaces, RoundingModes.HalfEven);
			}

			return p;
		}

		private BigInteger maxCoeffAbs() {
			BigInteger max = this.coeffs[0].Abs();

			for(int i = 1; i < this.coeffs.Length; i++) {
				BigInteger coeff = this.coeffs[i].Abs();

				if(coeff.CompareTo(max) > 0) {
					max = coeff;
				}
			}

			return max;
		}

		/// <summary>
		///     Takes each coefficient modulo a number.
		/// </summary>
		/// <param name="modulus"> </param>
		public virtual void mod(BigInteger modulus) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] % modulus;
			}
		}

		/// <summary>
		///     Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
		/// </summary>
		/// <returns> the sum of all coefficients </returns>
		internal virtual BigInteger sumCoeffs() {
			BigInteger sum = Constants.BIGINT_ZERO;

			for(int i = 0; i < this.coeffs.Length; i++) {
				sum = sum + this.coeffs[i];
			}

			return sum;
		}

		/// <summary>
		///     Makes a copy of the polynomial that is independent of the original.
		/// </summary>
		public virtual BigIntPolynomial clone() {
			return new BigIntPolynomial((BigInteger[]) this.coeffs.Clone());
		}

		public override int GetHashCode() {
			const int prime  = 31;
			int       result = 1;
			result = (prime * result) + this.coeffs.GetHashCode();

			return result;
		}

		public override bool Equals(object obj) {
			if(this == obj) {
				return true;
			}

			if(obj == null) {
				return false;
			}

			if(this.GetType() != obj.GetType()) {
				return false;
			}

			BigIntPolynomial other = (BigIntPolynomial) obj;

			if(!ArraysExtensions.AreEqual(this.coeffs, other.coeffs)) {
				return false;
			}

			return true;
		}
	}

}
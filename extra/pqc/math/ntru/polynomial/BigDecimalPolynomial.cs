using System;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A polynomial with <seealso cref="BigDecimal" /> coefficients.
	///     Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
	///     not but return the result as a new polynomial.
	/// </summary>
	public class BigDecimalPolynomial {
		private static readonly BigDecimal ONE_HALF = new BigDecimal("0.5");

		internal BigDecimal[] coeffs;

		/// <summary>
		///     Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
		/// </summary>
		/// <param name="N"> the number of coefficients </param>
		internal BigDecimalPolynomial(int N) {
			this.coeffs = new BigDecimal[N];

			for(int i = 0; i < N; i++) {
				this.coeffs[i] = BigDecimal.Zero;
			}
		}

		/// <summary>
		///     Constructs a new polynomial with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		internal BigDecimalPolynomial(BigDecimal[] coeffs) {
			this.coeffs = coeffs;
		}

		/// <summary>
		///     Constructs a <code>BigDecimalPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are
		///     independent of each other.
		/// </summary>
		/// <param name="p"> the original polynomial </param>
		public BigDecimalPolynomial(BigIntPolynomial p) {
			int N = p.coeffs.Length;
			this.coeffs = new BigDecimal[N];

			for(int i = 0; i < N; i++) {
				this.coeffs[i] = new BigDecimal(p.coeffs[i]);
			}
		}

		public virtual BigDecimal[] Coeffs {
			get {
				BigDecimal[] tmp = new BigDecimal[this.coeffs.Length];

				Buffer.BlockCopy(this.coeffs, 0, tmp, 0, this.coeffs.Length);

				return tmp;
			}
		}

		/// <summary>
		///     Divides all coefficients by 2.
		/// </summary>
		public virtual void halve() {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] * ONE_HALF;
			}
		}

		/// <summary>
		///     Multiplies the polynomial by another. Does not change this polynomial
		///     but returns the result as a new polynomial.
		/// </summary>
		/// <param name="poly2"> the polynomial to multiply by </param>
		/// <returns> a new polynomial </returns>
		public virtual BigDecimalPolynomial mult(BigIntPolynomial poly2) {
			return this.mult(new BigDecimalPolynomial(poly2));
		}

		/// <summary>
		///     Multiplies the polynomial by another, taking the indices mod N. Does not
		///     change this polynomial but returns the result as a new polynomial.
		/// </summary>
		/// <param name="poly2"> the polynomial to multiply by </param>
		/// <returns> a new polynomial </returns>
		public virtual BigDecimalPolynomial mult(BigDecimalPolynomial poly2) {
			int N = this.coeffs.Length;

			if(poly2.coeffs.Length != N) {
				throw new ArgumentException("Number of coefficients must be the same");
			}

			BigDecimalPolynomial c = this.multRecursive(poly2);

			if(c.coeffs.Length > N) {
				for(int k = N; k < c.coeffs.Length; k++) {
					c.coeffs[k - N] = c.coeffs[k - N] + c.coeffs[k];
				}

				c.coeffs = this.copyOf(c.coeffs, N);
			}

			return c;
		}

		/// <summary>
		///     Karazuba multiplication
		/// </summary>
		private BigDecimalPolynomial multRecursive(BigDecimalPolynomial poly2) {
			BigDecimal[] a = this.coeffs;
			BigDecimal[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;

			if(n <= 1) {
				//TODO: does this clone work like it should?
				BigDecimal[] c = ArraysExtensions.Clone(this.coeffs);

				for(int i = 0; i < this.coeffs.Length; i++) {
					c[i] = c[i] * poly2.coeffs[0];
				}

				return new BigDecimalPolynomial(c);
			} else {
				int n1 = n / 2;

				BigDecimalPolynomial a1 = new BigDecimalPolynomial(this.copyOf(a, n1));
				BigDecimalPolynomial a2 = new BigDecimalPolynomial(this.copyOfRange(a, n1, n));
				BigDecimalPolynomial b1 = new BigDecimalPolynomial(this.copyOf(b, n1));
				BigDecimalPolynomial b2 = new BigDecimalPolynomial(this.copyOfRange(b, n1, n));

				BigDecimalPolynomial A = a1.clone();
				A.add(a2);
				BigDecimalPolynomial B = b1.clone();
				B.add(b2);

				BigDecimalPolynomial c1 = a1.multRecursive(b1);
				BigDecimalPolynomial c2 = a2.multRecursive(b2);
				BigDecimalPolynomial c3 = A.multRecursive(B);
				c3.sub(c1);
				c3.sub(c2);

				BigDecimalPolynomial c = new BigDecimalPolynomial((2 * n) - 1);

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
		///     Adds another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void add(BigDecimalPolynomial b) {
			if(b.coeffs.Length > this.coeffs.Length) {
				int N = this.coeffs.Length;
				this.coeffs = this.copyOf(this.coeffs, b.coeffs.Length);

				for(int i = N; i < this.coeffs.Length; i++) {
					this.coeffs[i] = BigDecimal.Zero;
				}
			}

			for(int i = 0; i < b.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] + b.coeffs[i];
			}
		}

		/// <summary>
		///     Subtracts another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> </param>
		internal virtual void sub(BigDecimalPolynomial b) {
			if(b.coeffs.Length > this.coeffs.Length) {
				int N = this.coeffs.Length;
				this.coeffs = this.copyOf(this.coeffs, b.coeffs.Length);

				for(int i = N; i < this.coeffs.Length; i++) {
					this.coeffs[i] = BigDecimal.Zero;
				}
			}

			for(int i = 0; i < b.coeffs.Length; i++) {
				this.coeffs[i] = this.coeffs[i] - b.coeffs[i];
			}
		}

		/// <summary>
		///     Rounds all coefficients to the nearest integer.
		/// </summary>
		/// <returns> a new polynomial with <code>BigInteger</code> coefficients </returns>
		public virtual BigIntPolynomial round() {
			int              N = this.coeffs.Length;
			BigIntPolynomial p = new BigIntPolynomial(N);

			for(int i = 0; i < N; i++) {
				p.coeffs[i] = this.coeffs[i].SetScale(0, RoundingModes.HalfEven).ToBigInteger();
			}

			return p;
		}

		/// <summary>
		///     Makes a copy of the polynomial that is independent of the original.
		/// </summary>
		public virtual BigDecimalPolynomial clone() {
			return new BigDecimalPolynomial((BigDecimal[]) this.coeffs.Clone());
		}

		private BigDecimal[] copyOf(BigDecimal[] a, int length) {
			BigDecimal[] tmp = new BigDecimal[length];

			Buffer.BlockCopy(a, 0, tmp, 0, a.Length < length ? a.Length : length);

			return tmp;
		}

		private BigDecimal[] copyOfRange(BigDecimal[] a, int from, int to) {
			int          newLength = to - from;
			BigDecimal[] tmp       = new BigDecimal[to - from];

			Buffer.BlockCopy(a, from, tmp, 0, (a.Length - from) < newLength ? a.Length - from : newLength);

			return tmp;
		}
	}

}
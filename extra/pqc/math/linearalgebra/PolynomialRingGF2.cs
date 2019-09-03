using System;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	/// <summary>
	///     This class describes operations with polynomials over finite field GF(2), i e
	///     polynomial ring R = GF(2)[X]. All operations are defined only for polynomials
	///     with degree &lt;=32. For the polynomial representation the map f: R-&gt;Z,
	///     poly(X)-&gt;poly(2) is used, where integers have the binary representation. For
	///     example: X^7+X^3+X+1 -&gt; (00...0010001011)=139 Also for polynomials type
	///     Integer is used.
	/// </summary>
	/// <seealso cref= GF2mField
	/// </seealso>
	public sealed class PolynomialRingGF2 {

		/// <summary>
		///     Default constructor (private).
		/// </summary>
		private PolynomialRingGF2() {
			// empty
		}

		/// <summary>
		///     Return sum of two polyomials
		/// </summary>
		/// <param name="p"> polynomial </param>
		/// <param name="q"> polynomial </param>
		/// <returns> p+q </returns>
		public static int add(int p, int q) {
			return p ^ q;
		}

		/// <summary>
		///     Return product of two polynomials
		/// </summary>
		/// <param name="p"> polynomial </param>
		/// <param name="q"> polynomial </param>
		/// <returns> p*q </returns>
		public static long multiply(int p, int q) {
			long result = 0;

			if(q != 0) {
				long q1 = q & 0x00000000ffffffffL;

				while(p != 0) {
					byte b = (byte) (p & 0x01);

					if(b == 1) {
						result ^= q1;
					}

					p  =   (int) ((uint) p >> 1);
					q1 <<= 1;

				}
			}

			return result;
		}

		/// <summary>
		///     Compute the product of two polynomials modulo a third polynomial.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="b"> the second polynomial </param>
		/// <param name="r"> the reduction polynomial </param>
		/// <returns>
		///     <tt>a * b mod r</tt>
		/// </returns>
		public static int modMultiply(int a, int b, int r) {
			int result = 0;
			int p      = remainder(a, r);
			int q      = remainder(b, r);

			if(q != 0) {
				int d = 1 << degree(r);

				while(p != 0) {
					byte pMod2 = (byte) (p & 0x01);

					if(pMod2 == 1) {
						result ^= q;
					}

					p =   (int) ((uint) p >> 1);
					q <<= 1;

					if(q >= d) {
						q ^= r;
					}
				}
			}

			return result;
		}

		/// <summary>
		///     Return the degree of a polynomial
		/// </summary>
		/// <param name="p"> polynomial p </param>
		/// <returns> degree(p) </returns>
		public static int degree(int p) {
			int result = -1;

			while(p != 0) {
				result++;
				p = (int) ((uint) p >> 1);
			}

			return result;
		}

		/// <summary>
		///     Return the degree of a polynomial
		/// </summary>
		/// <param name="p"> polynomial p </param>
		/// <returns> degree(p) </returns>
		public static int degree(long p) {
			int result = 0;

			while(p != 0) {
				result++;
				p = (long) ((ulong) p >> 1);
			}

			return result - 1;
		}

		/// <summary>
		///     Return the remainder of a polynomial division of two polynomials.
		/// </summary>
		/// <param name="p"> dividend </param>
		/// <param name="q"> divisor </param>
		/// <returns>
		///     <tt>p mod q</tt>
		/// </returns>
		public static int remainder(int p, int q) {
			int result = p;

			if(q == 0) {
				Console.Error.WriteLine("Error: to be divided by 0");

				return 0;
			}

			while(degree(result) >= degree(q)) {
				result ^= q << (degree(result) - degree(q));
			}

			return result;
		}

		/// <summary>
		///     Return the rest of devision two polynomials
		/// </summary>
		/// <param name="p"> polinomial </param>
		/// <param name="q"> polinomial </param>
		/// <returns> p mod q </returns>
		public static int rest(long p, int q) {
			long p1 = p;

			if(q == 0) {
				Console.Error.WriteLine("Error: to be divided by 0");

				return 0;
			}

			long q1 = q & 0x00000000ffffffffL;

			while((long) ((ulong) p1 >> 32) != 0) {
				p1 ^= q1 << (degree(p1) - degree(q1));
			}

			int result = unchecked((int) (p1 & 0xffffffff));

			while(degree(result) >= degree(q)) {
				result ^= q << (degree(result) - degree(q));
			}

			return result;
		}

		/// <summary>
		///     Return the greatest common divisor of two polynomials
		/// </summary>
		/// <param name="p"> polinomial </param>
		/// <param name="q"> polinomial </param>
		/// <returns> GCD(p, q) </returns>
		public static int gcd(int p, int q) {
			int a, b, c;
			a = p;
			b = q;

			while(b != 0) {
				c = remainder(a, b);
				a = b;
				b = c;

			}

			return a;
		}

		/// <summary>
		///     Checking polynomial for irreducibility
		/// </summary>
		/// <param name="p"> polinomial </param>
		/// <returns> true if p is irreducible and false otherwise </returns>
		public static bool isIrreducible(int p) {
			if(p == 0) {
				return false;
			}

			int d = (int) ((uint) degree(p) >> 1);
			int u = 2;

			for(int i = 0; i < d; i++) {
				u = modMultiply(u, u, p);

				if(gcd(u ^ 2, p) != 1) {
					return false;
				}
			}

			return true;
		}

		/// <summary>
		///     Creates irreducible polynomial with degree d
		/// </summary>
		/// <param name="deg"> polynomial degree </param>
		/// <returns> irreducible polynomial p </returns>
		public static int getIrreduciblePolynomial(int deg) {
			if(deg < 0) {
				Console.Error.WriteLine("The Degree is negative");

				return 0;
			}

			if(deg > 31) {
				Console.Error.WriteLine("The Degree is more then 31");

				return 0;
			}

			if(deg == 0) {
				return 1;
			}

			int a = 1 << deg;
			a++;
			int b = 1 << (deg + 1);

			for(int i = a; i < b; i += 2) {
				if(isIrreducible(i)) {
					return i;
				}
			}

			return 0;
		}
	}

}
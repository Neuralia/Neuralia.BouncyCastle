using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Neuralia.BouncyCastle.extra.Security;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     Class of number-theory related functions for use with integers represented as
	///     <tt>int</tt>'s or <tt>BigInteger</tt> objects.
	/// </summary>
	public sealed class IntegerFunctions {

		private static readonly BigInteger ZERO = BigInteger.ValueOf(0);

		private static readonly BigInteger ONE = BigInteger.ValueOf(1);

		private static readonly BigInteger TWO = BigInteger.ValueOf(2);

		private static readonly BigInteger FOUR = BigInteger.ValueOf(4);

		private static readonly int[] SMALL_PRIMES = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41};

		private static readonly long SMALL_PRIME_PRODUCT = 3L * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31 * 37 * 41;

		private static SecureRandom sr;

		// the jacobi function uses this lookup table
		private static readonly int[] jacobiTable = {0, 1, 0, -1, 0, -1, 0, 1};

		private IntegerFunctions() {
			// empty
		}

		/// <summary>
		///     Computes the value of the Jacobi symbol (A|B). The following properties
		///     hold for the Jacobi symbol which makes it a very efficient way to
		///     evaluate the Legendre symbol
		///     <para>
		///         (A|B) = 0 IF Gcd(A,B) &gt; 1
		///         <br>
		///             (-1|B) = 1 IF n = 1 (mod 1)
		///             <br>
		///                 (-1|B) = -1 IF n = 3 (mod 4)
		///                 <br>
		///                     (A|B) (C|B) = (AC|B)
		///                     <br>
		///                         (A|B) (A|C) = (A|CB)
		///                         <br>
		///                             (A|B) = (C|B) IF A = C (mod B)
		///                             <br>
		///                                 (2|B) = 1 IF N = 1 OR 7 (mod 8)
		///                                 <br>
		///                                     (2|B) = 1 IF N = 3 OR 5 (mod 8)
		///     </para>
		/// </summary>
		/// <param name="A"> integer value </param>
		/// <param name="B"> integer value </param>
		/// <returns> value of the jacobi symbol (A|B) </returns>
		public static int jacobi(BigInteger A, BigInteger B) {
			BigInteger a, b, v;
			long       k = 1;

			k = 1;

			// test trivial cases
			if(B.Equals(ZERO)) {
				a = A.Abs();

				return a.Equals(ONE) ? 1 : 0;
			}

			if(!A.TestBit(0) && !B.TestBit(0)) {
				return 0;
			}

			a = A;
			b = B;

			if(b.Signum() == -1) {
				// b < 0
				b = -b; // b = -b

				if(a.Signum() == -1) {
					k = -1;
				}
			}

			v = ZERO;

			while(!b.TestBit(0)) {
				v = v + ONE; // v = v + 1
				b = b / TWO; // b = b/2
			}

			if(v.TestBit(0)) {
				k = k * jacobiTable[a.ToInt32() & 7];
			}

			if(a.Signum() < 0) {
				// a < 0
				if(b.TestBit(1)) {
					k = -k; // k = -k
				}

				a = -a; // a = -a
			}

			// main loop
			while(a.Signum() != 0) {
				v = ZERO;

				while(!a.TestBit(0)) {
					// a is even
					v = v + ONE;
					a = a / TWO;
				}

				if(v.TestBit(0)) {
					k = k * jacobiTable[b.ToInt32() & 7];
				}

				if(a.CompareTo(b) < 0) {
					// a < b
					// swap and correct intermediate result
					BigInteger x = a;
					a = b;
					b = x;

					if(a.TestBit(1) && b.TestBit(1)) {
						k = -k;
					}
				}

				a = a - b;
			}

			return b.Equals(ONE) ? (int) k : 0;
		}

		/// <summary>
		///     Computes the square root of a BigInteger modulo a prime employing the
		///     Shanks-Tonelli algorithm.
		/// </summary>
		/// <param name="a"> value out of which we extract the square root </param>
		/// <param name="p"> prime modulus that determines the underlying field </param>
		/// <returns>
		///     a number <tt>b</tt> such that b<sup>2</sup> = a (mod p) if
		///     <tt>a</tt> is a quadratic residue modulo <tt>p</tt>.
		/// </returns>
		/// <exception cref="IllegalArgumentException"> if <tt>a</tt> is a quadratic non-residue modulo <tt>p</tt> </exception>
		public static BigInteger ressol(BigInteger a, BigInteger p) {

			BigInteger v = null;

			if(a.CompareTo(ZERO) < 0) {
				a = a + p;
			}

			if(a.Equals(ZERO)) {
				return ZERO;
			}

			if(p.Equals(TWO)) {
				return a;
			}

			// p = 3 mod 4
			if(p.TestBit(0) && p.TestBit(1)) {
				if(jacobi(a, p) == 1) {
					// a quadr. residue mod p
					v = p + ONE; // v = p+1
					v = v >> 2;  // v = v/4

					return a.ModPow(v, p); // return a^v mod p

					// return --> a^((p+1)/4) mod p
				}

				throw new ArgumentException("No quadratic residue: " + a + ", " + p);
			}

			long t = 0;

			// initialization
			// compute k and s, where p = 2^s (2k+1) +1

			BigInteger k = p - ONE; // k = p-1
			long       s = 0;

			while(!k.TestBit(0)) {
				// while k is even
				s++;        // s = s+1
				k = k >> 1; // k = k/2
			}

			k = k - ONE; // k = k - 1
			k = k >> 1;  // k = k/2

			// initial values
			BigInteger r = a.ModPow(k, p); // r = a^k mod p

			BigInteger n = r * r.Remainder(p); // n = r^2 % p
			n = n * a.Remainder(p);            // n = n * a % p
			r = r * a.Remainder(p);            // r = r * a %p

			if(n.Equals(ONE)) {
				return r;
			}

			// non-quadratic residue
			BigInteger z = TWO; // z = 2

			while(jacobi(z, p) == 1) {
				// while z quadratic residue
				z = z + ONE; // z = z + 1
			}

			v = k;
			v = v * TWO;                   // v = 2k
			v = v + ONE;                   // v = 2k + 1
			BigInteger c = z.ModPow(v, p); // c = z^v mod p

			// iteration
			while(n.CompareTo(ONE) == 1) {
				// n > 1
				k = n; // k = n
				t = s; // t = s
				s = 0;

				while(!k.Equals(ONE)) {
					// k != 1
					k = (k * k) % p; // k = k^2 % p
					s++;             // s = s + 1
				}

				t -= s; // t = t - s

				if(t == 0) {
					throw new ArgumentException("No quadratic residue: " + a + ", " + p);
				}

				v = ONE;

				for(long i = 0; i < (t - 1); i++) {
					v = v << 1; // v = 1 * 2^(t - 1)
				}

				c = c.ModPow(v, p);           // c = c^v mod p
				r = r       * c.Remainder(p); // r = r * c % p
				c = c       * c.Remainder(p); // c = c^2 % p
				n = (n * c) % p;              // n = n * c % p
			}

			return r;
		}

		/// <summary>
		///     Computes the greatest common divisor of the two specified integers
		/// </summary>
		/// <param name="u"> - first integer </param>
		/// <param name="v"> - second integer </param>
		/// <returns> Gcd(a, b) </returns>
		public static int Gcd(int u, int v) {
			return BigInteger.ValueOf(u).Gcd(BigInteger.ValueOf(v)).ToInt32();
		}

		/// <summary>
		///     Extended euclidian algorithm (computes Gcd and representation).
		/// </summary>
		/// <param name="a"> the first integer </param>
		/// <param name="b"> the second integer </param>
		/// <returns> <tt>(g,u,v)</tt>, where <tt>g = Gcd(Abs(a),Abs(b)) = ua + vb</tt> </returns>
		public static int[] extGCD(int a, int b) {
			BigInteger   ba      = BigInteger.ValueOf(a);
			BigInteger   bb      = BigInteger.ValueOf(b);
			BigInteger[] bresult = extGcd(ba, bb);
			int[]        result  = new int[3];
			result[0] = bresult[0].ToInt32();
			result[1] = bresult[1].ToInt32();
			result[2] = bresult[2].ToInt32();

			return result;
		}

		public static BigInteger DivideAndRound(BigInteger a, BigInteger b) {
			if(a.Signum() < 0) {
				return -DivideAndRound(-a, b);
			}

			if(b.Signum() < 0) {
				return -DivideAndRound(a, -b);
			}

			return a.ShiftLeft(BigInteger.ValueOf(1).Add(b).Divide(b << 1));
		}

		public static BigInteger[] DivideAndRound(BigInteger[] a, BigInteger b) {
			BigInteger[] @out = new BigInteger[a.Length];

			for(int i = 0; i < a.Length; i++) {
				@out[i] = DivideAndRound(a[i], b);
			}

			return @out;
		}

		/// <summary>
		///     Compute the smallest integer that is greater than or equal to the
		///     logarithm to the base 2 of the given BigInteger.
		/// </summary>
		/// <param name="a"> the integer </param>
		/// <returns> ceil[log(a)] </returns>
		public static int ceilLog(BigInteger a) {
			int        result = 0;
			BigInteger p      = ONE;

			while(p.CompareTo(a) < 0) {
				result++;
				p = p << 1;
			}

			return result;
		}

		/// <summary>
		///     Compute the smallest integer that is greater than or equal to the
		///     logarithm to the base 2 of the given integer.
		/// </summary>
		/// <param name="a"> the integer </param>
		/// <returns> ceil[log(a)] </returns>
		public static int ceilLog(int a) {
			int log = 0;
			int i   = 1;

			while(i < a) {
				i <<= 1;
				log++;
			}

			return log;
		}

		/// <summary>
		///     Compute <tt>ceil(log_256 n)</tt>, the number of bytes needed to encode
		///     the integer <tt>n</tt>.
		/// </summary>
		/// <param name="n"> the integer </param>
		/// <returns> the number of bytes needed to encode <tt>n</tt> </returns>
		public static int ceilLog256(int n) {
			if(n == 0) {
				return 1;
			}

			int m;

			if(n < 0) {
				m = -n;
			} else {
				m = n;
			}

			int d = 0;

			while(m > 0) {
				d++;
				m = (int) ((uint) m >> 8);
			}

			return d;
		}

		/// <summary>
		///     Compute <tt>ceil(log_256 n)</tt>, the number of bytes needed to encode
		///     the long integer <tt>n</tt>.
		/// </summary>
		/// <param name="n"> the long integer </param>
		/// <returns> the number of bytes needed to encode <tt>n</tt> </returns>
		public static int ceilLog256(long n) {
			if(n == 0) {
				return 1;
			}

			long m;

			if(n < 0) {
				m = -n;
			} else {
				m = n;
			}

			int d = 0;

			while(m > 0) {
				d++;
				m = (long) ((ulong) m >> 8);
			}

			return d;
		}

		/// <summary>
		///     Compute the integer part of the logarithm to the base 2 of the given
		///     integer.
		/// </summary>
		/// <param name="a"> the integer </param>
		/// <returns> floor[log(a)] </returns>
		public static int floorLog(BigInteger a) {
			int        result = -1;
			BigInteger p      = ONE;

			while(p.CompareTo(a) <= 0) {
				result++;
				p = p << 1;
			}

			return result;
		}

		/// <summary>
		///     Compute the integer part of the logarithm to the base 2 of the given
		///     integer.
		/// </summary>
		/// <param name="a"> the integer </param>
		/// <returns> floor[log(a)] </returns>
		public static int floorLog(int a) {
			int h = 0;

			if(a <= 0) {
				return -1;
			}

			int p = (int) ((uint) a >> 1);

			while(p > 0) {
				h++;
				p = (int) ((uint) p >> 1);
			}

			return h;
		}

		/// <summary>
		///     Compute the largest <tt>h</tt> with <tt>2^h | a</tt> if <tt>a!=0</tt>.
		/// </summary>
		/// <param name="a"> an integer </param>
		/// <returns>
		///     the largest <tt>h</tt> with <tt>2^h | a</tt> if <tt>a!=0</tt>,
		///     <tt>0</tt> otherwise
		/// </returns>
		public static int maxPower(int a) {
			int h = 0;

			if(a != 0) {
				int p = 1;

				while((a & p) == 0) {
					h++;
					p <<= 1;
				}
			}

			return h;
		}

		/// <param name="a"> an integer </param>
		/// <returns>
		///     the number of ones in the binary representation of an integer
		///     <tt>a</tt>
		/// </returns>
		public static int bitCount(int a) {
			int h = 0;

			while(a != 0) {
				h += a & 1;
				a =  (int) ((uint) a >> 1);
			}

			return h;
		}

		/// <summary>
		///     determines the order of g modulo p, p prime and 1 &lt; g &lt; p. This algorithm
		///     is only efficient for small p (see X9.62-1998, p. 68).
		/// </summary>
		/// <param name="g"> an integer with 1 &lt; g &lt; p </param>
		/// <param name="p"> a prime </param>
		/// <returns>
		///     the order k of g (that is k is the smallest integer with
		///     g<sup>k</sup> = 1 mod p
		/// </returns>
		public static int order(int g, int p) {
			int b, j;

			b = g % p; // Reduce g mod p first.
			j = 1;

			// Check whether g == 0 mod p (avoiding endless loop).
			if(b == 0) {
				throw new ArgumentException(g + " is not an element of Z/(" + p + "Z)^*; it is not meaningful to compute its order.");
			}

			// Compute the order of g mod p:
			while(b != 1) {
				b *= g;
				b %= p;

				if(b < 0) {
					b += p;
				}

				j++;
			}

			return j;
		}

		/// <summary>
		///     Reduces an integer into a given interval
		/// </summary>
		/// <param name="n">     - the integer </param>
		/// <param name="begin"> - left bound of the interval </param>
		/// <param name="end">   - right bound of the interval </param>
		/// <returns> <tt>n</tt> reduced into <tt>[begin,end]</tt> </returns>
		public static BigInteger reduceInto(BigInteger n, BigInteger begin, BigInteger end) {
			return n - (begin % end) - begin.Add(begin);
		}

		/// <summary>
		///     Compute <tt>a<sup>e</sup></tt>.
		/// </summary>
		/// <param name="a"> the base </param>
		/// <param name="e"> the exponent </param>
		/// <returns>
		///     <tt>a<sup>e</sup></tt>
		/// </returns>
		public static int pow(int a, int e) {
			int result = 1;

			while(e > 0) {
				if((e & 1) == 1) {
					result *= a;
				}

				a *= a;
				e =  (int) ((uint) e >> 1);
			}

			return result;
		}

		/// <summary>
		///     Compute <tt>a<sup>e</sup></tt>.
		/// </summary>
		/// <param name="a"> the base </param>
		/// <param name="e"> the exponent </param>
		/// <returns>
		///     <tt>a<sup>e</sup></tt>
		/// </returns>
		public static long pow(long a, int e) {
			long result = 1;

			while(e > 0) {
				if((e & 1) == 1) {
					result *= a;
				}

				a *= a;
				e =  (int) ((uint) e >> 1);
			}

			return result;
		}

		/// <summary>
		///     Compute <tt>a<sup>e</sup> mod n</tt>.
		/// </summary>
		/// <param name="a"> the base </param>
		/// <param name="e"> the exponent </param>
		/// <param name="n"> the modulus </param>
		/// <returns>
		///     <tt>a<sup>e</sup> mod n</tt>
		/// </returns>
		public static int ModPow(int a, int e, int n) {
			if((n <= 0) || ((n * n) > int.MaxValue) || (e < 0)) {
				return 0;
			}

			int result = 1;
			a = ((a % n) + n) % n;

			while(e > 0) {
				if((e & 1) == 1) {
					result = (result * a) % n;
				}

				a = (a * a) % n;
				e = (int) ((uint) e >> 1);
			}

			return result;
		}

		/// <summary>
		///     Extended euclidian algorithm (computes Gcd and representation).
		/// </summary>
		/// <param name="a"> - the first integer </param>
		/// <param name="b"> - the second integer </param>
		/// <returns> <tt>(d,u,v)</tt>, where <tt>d = Gcd(a,b) = ua + vb</tt> </returns>
		public static BigInteger[] extGcd(BigInteger a, BigInteger b) {
			BigInteger u = ONE;
			BigInteger v = ZERO;
			BigInteger d = a;

			if(b.Signum() != 0) {
				BigInteger v1 = ZERO;
				BigInteger v3 = b;

				while(v3.Signum() != 0) {
					BigInteger[] tmp = d.DivideAndRemainder(v3);
					BigInteger   q   = tmp[0];
					BigInteger   t3  = tmp[1];
					BigInteger   t1  = u - (q * v1);
					u  = v1;
					d  = v3;
					v1 = t1;
					v3 = t3;
				}

				v = d - (a * u).Divide(b);
			}

			return new[] {d, u, v};
		}

		/// <summary>
		///     Computation of the least common multiple of a set of BigIntegers.
		/// </summary>
		/// <param name="numbers"> - the set of numbers </param>
		/// <returns> the lcm(numbers) </returns>
		public static BigInteger leastCommonMultiple(BigInteger[] numbers) {
			int        n      = numbers.Length;
			BigInteger result = numbers[0];

			for(int i = 1; i < n; i++) {
				BigInteger Gcd = result.Gcd(numbers[i]);
				result = result * numbers[i].Divide(Gcd);
			}

			return result;
		}

		/// <summary>
		///     Returns a long integer whose value is <tt>(a mod m</tt>). This method
		///     differs from <tt>%</tt> in that it always returns a <i>non-negative</i>
		///     integer.
		/// </summary>
		/// <param name="a"> value on which the modulo operation has to be performed. </param>
		/// <param name="m"> the modulus. </param>
		/// <returns>
		///     <tt>a mod m</tt>
		/// </returns>
		public static long mod(long a, long m) {
			long result = a % m;

			if(result < 0) {
				result += m;
			}

			return result;
		}

		/// <summary>
		///     Computes the modular inverse of an integer a
		/// </summary>
		/// <param name="a">   - the integer to invert </param>
		/// <param name="mod"> - the modulus </param>
		/// <returns>
		///     <tt>a<sup>-1</sup> mod n</tt>
		/// </returns>
		public static int ModInverse(int a, int mod) {
			return BigInteger.ValueOf(a).ModInverse(BigInteger.ValueOf(mod)).ToInt32();
		}

		/// <summary>
		///     Computes the modular inverse of an integer a
		/// </summary>
		/// <param name="a">   - the integer to invert </param>
		/// <param name="mod"> - the modulus </param>
		/// <returns>
		///     <tt>a<sup>-1</sup> mod n</tt>
		/// </returns>
		public static long ModInverse(long a, long mod) {
			return BigInteger.ValueOf(a).ModInverse(BigInteger.ValueOf(mod)).ToInt64();
		}

		/// <summary>
		///     Tests whether an integer <tt>a</tt> is power of another integer
		///     <tt>p</tt>.
		/// </summary>
		/// <param name="a"> - the first integer </param>
		/// <param name="p"> - the second integer </param>
		/// <returns> n if a = p^n or -1 otherwise </returns>
		public static int isPower(int a, int p) {
			if(a <= 0) {
				return -1;
			}

			int n = 0;
			int d = a;

			while(d > 1) {
				if((d % p) != 0) {
					return -1;
				}

				d /= p;
				n++;
			}

			return n;
		}

		/// <summary>
		///     Find and return the least non-trivial divisor of an integer <tt>a</tt>.
		/// </summary>
		/// <param name="a"> - the integer </param>
		/// <returns> divisor p &gt;1 or 1 if a = -1,0,1 </returns>
		public static int leastDiv(int a) {
			if(a < 0) {
				a = -a;
			}

			if(a == 0) {
				return 1;
			}

			if((a & 1) == 0) {
				return 2;
			}

			int p = 3;

			while(p <= (a / p)) {
				if((a % p) == 0) {
					return p;
				}

				p += 2;
			}

			return a;
		}

		/// <summary>
		///     Miller-Rabin-Test, determines wether the given integer is probably prime
		///     or composite. This method returns <tt>true</tt> if the given integer is
		///     prime with probability <tt>1 - 2<sup>-20</sup></tt>.
		/// </summary>
		/// <param name="n"> the integer to test for primality </param>
		/// <returns>
		///     <tt>true</tt> if the given integer is prime with probability
		///     2<sup>-100</sup>, <tt>false</tt> otherwise
		/// </returns>
		public static bool isPrime(int n) {
			if(n < 2) {
				return false;
			}

			if(n == 2) {
				return true;
			}

			if((n & 1) == 0) {
				return false;
			}

			if(n < 42) {
				for(int i = 0; i < SMALL_PRIMES.Length; i++) {
					if(n == SMALL_PRIMES[i]) {
						return true;
					}
				}
			}

			if(((n % 3) == 0) || ((n % 5) == 0) || ((n % 7) == 0) || ((n % 11) == 0) || ((n % 13) == 0) || ((n % 17) == 0) || ((n % 19) == 0) || ((n % 23) == 0) || ((n % 29) == 0) || ((n % 31) == 0) || ((n % 37) == 0) || ((n % 41) == 0)) {
				return false;
			}

			return BigInteger.ValueOf(n).IsProbablePrime(20);
		}

		/// <summary>
		///     Short trial-division test to find out whether a number is not prime. This
		///     test is usually used before a Miller-Rabin primality test.
		/// </summary>
		/// <param name="candidate"> the number to test </param>
		/// <returns>
		///     <tt>true</tt> if the number has no factor of the tested primes,
		///     <tt>false</tt> if the number is definitely composite
		/// </returns>
		public static bool passesSmallPrimeTest(BigInteger candidate) {

			int[] smallPrime = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499};

			for(int i = 0; i < smallPrime.Length; i++) {
				if(candidate.Mod(BigInteger.ValueOf(smallPrime[i])).Equals(ZERO)) {
					return false;
				}
			}

			return true;
		}

		/// <summary>
		///     Returns the largest prime smaller than the given integer
		/// </summary>
		/// <param name="n"> - upper bound </param>
		/// <returns>
		///     the largest prime smaller than <tt>n</tt>, or <tt>1</tt> if
		///     <tt>n &lt;= 2</tt>
		/// </returns>
		public static int nextSmallerPrime(int n) {
			if(n <= 2) {
				return 1;
			}

			if(n == 3) {
				return 2;
			}

			if((n & 1) == 0) {
				n--;
			} else {
				n -= 2;
			}

			while((n > 3) & !isPrime(n)) {
				n -= 2;
			}

			return n;
		}

		/// <summary>
		///     Compute the next probable prime greater than <tt>n</tt> with the
		///     specified certainty.
		/// </summary>
		/// <param name="n">         a integer number </param>
		/// <param name="certainty"> the certainty that the generated number is prime </param>
		/// <returns> the next prime greater than <tt>n</tt> </returns>
		public static BigInteger nextProbablePrime(BigInteger n, int certainty) {

			if((n.Signum() < 0) || (n.Signum() == 0) || n.Equals(ONE)) {
				return TWO;
			}

			BigInteger result = n + ONE;

			// Ensure an odd number
			if(!result.TestBit(0)) {
				result = result + ONE;
			}

			while(true) {
				// Do cheap "pre-test" if applicable
				if(result.BitLength > 6) {
					long r = result.Remainder(BigInteger.ValueOf(SMALL_PRIME_PRODUCT)).ToInt64();

					if(((r % 3) == 0) || ((r % 5) == 0) || ((r % 7) == 0) || ((r % 11) == 0) || ((r % 13) == 0) || ((r % 17) == 0) || ((r % 19) == 0) || ((r % 23) == 0) || ((r % 29) == 0) || ((r % 31) == 0) || ((r % 37) == 0) || ((r % 41) == 0)) {
						result = result + TWO;

						continue; // Candidate is composite; try another
					}
				}

				// All candidates of bitLength 2 and 3 are prime by this point
				if(result.BitLength < 4) {
					return result;
				}

				// The expensive test
				if(result.IsProbablePrime(certainty)) {
					return result;
				}

				result = result + TWO;
			}
		}

		/// <summary>
		///     Compute the next probable prime greater than <tt>n</tt> with the default
		///     certainty (20).
		/// </summary>
		/// <param name="n"> a integer number </param>
		/// <returns> the next prime greater than <tt>n</tt> </returns>
		public static BigInteger nextProbablePrime(BigInteger n) {
			return nextProbablePrime(n, 20);
		}

		/// <summary>
		///     Computes the next prime greater than n.
		/// </summary>
		/// <param name="n"> a integer number </param>
		/// <returns> the next prime greater than n </returns>
		public static BigInteger nextPrime(long n) {
			long i;
			bool found  = false;
			long result = 0;

			if(n <= 1) {
				return BigInteger.ValueOf(2);
			}

			if(n == 2) {
				return BigInteger.ValueOf(3);
			}

			for(i = n + 1 + (n & 1); (i <= (n << 1)) && !found; i += 2) {
				for(long j = 3; (j <= (i >> 1)) && !found; j += 2) {
					if((i % j) == 0) {
						found = true;
					}
				}

				if(found) {
					found = false;
				} else {
					result = i;
					found  = true;
				}
			}

			return BigInteger.ValueOf(result);
		}

		/// <summary>
		///     Computes the binomial coefficient (n|t) ("n over t"). Formula:
		///     <ul>
		///         <li>if n !=0 and t != 0 then (n|t) = Mult(i=1, t): (n-(i-1))/i</li>
		///         <li>if t = 0 then (n|t) = 1</li>
		///         <li>if n = 0 and t &gt; 0 then (n|t) = 0</li>
		///     </ul>
		/// </summary>
		/// <param name="n"> - the "upper" integer </param>
		/// <param name="t"> - the "lower" integer </param>
		/// <returns> the binomialcoefficient "n over t" as BigInteger </returns>
		public static BigInteger binomial(int n, int t) {

			BigInteger result = ONE;

			if(n == 0) {
				if(t == 0) {
					return result;
				}

				return ZERO;
			}

			// the property (n|t) = (n|n-t) be used to reduce numbers of operations
			if(t > (int) ((uint) n >> 1)) {
				t = n - t;
			}

			for(int i = 1; i <= t; i++) {
				result = (result.Multiply(BigInteger.ValueOf(n - (i - 1)))).Divide(BigInteger.ValueOf(i));
			}

			return result;
		}

		public static BigInteger randomize(BigInteger upperBound) {
			if(sr == null) {
				sr = new BetterSecureRandom();
			}

			return randomize(upperBound, sr);
		}

		public static BigInteger randomize(BigInteger upperBound, SecureRandom prng) {
			int        blen      = upperBound.BitLength;
			BigInteger randomNum = BigInteger.ValueOf(0);

			if(prng == null) {
				prng = sr ?? new BetterSecureRandom();
			}

			for(int i = 0; i < 20; i++) {
				randomNum = new BigInteger(blen, prng);

				if(randomNum.CompareTo(upperBound) < 0) {
					return randomNum;
				}
			}

			return randomNum % upperBound;
		}

		/// <summary>
		///     Extract the truncated square root of a BigInteger.
		/// </summary>
		/// <param name="a"> - value out of which we extract the square root </param>
		/// <returns> the truncated square root of <tt>a</tt> </returns>
		public static BigInteger squareRoot(BigInteger a) {
			int        bl;
			BigInteger result, Remainder, b;

			if(a.CompareTo(ZERO) < 0) {
				throw new ArithmeticException("cannot extract root of negative number" + a + ".");
			}

			bl        = a.BitLength;
			result    = ZERO;
			Remainder = ZERO;

			// if the bit length is odd then extra step
			if((bl & 1) != 0) {
				result = result + ONE;
				bl--;
			}

			while(bl > 0) {
				Remainder = Remainder * FOUR;
				Remainder = Remainder + BigInteger.ValueOf((a.TestBit(--bl) ? 2 : 0) + (a.TestBit(--bl) ? 1 : 0));
				b         = result * FOUR.Add(ONE);
				result    = result * TWO;

				if(Remainder.CompareTo(b) != -1) {
					result    = result    + ONE;
					Remainder = Remainder - b;
				}
			}

			return result;
		}

		/// <summary>
		///     Takes an approximation of the root from an integer base, using newton's
		///     algorithm
		/// </summary>
		/// <param name="base"> the base to take the root from </param>
		/// <param name="root"> the root, for example 2 for a square root </param>
		public static float intRoot(int @base, int root) {
			float gNew    = @base / root;
			float gOld    = 0;
			int   counter = 0;

			while(Math.Abs(gOld - gNew) > 0.0001) {
				float gPow = floatPow(gNew, root);

				while(float.IsInfinity(gPow)) {
					gNew = (gNew + gOld) / 2;
					gPow = floatPow(gNew, root);
				}

				counter += 1;
				gOld    =  gNew;
				gNew    =  gOld - ((gPow - @base) / (root * floatPow(gOld, root - 1)));
			}

			return gNew;
		}

		/// <summary>
		///     int power of a base float, only use for small ints
		/// </summary>
		/// <param name="f"> base float </param>
		/// <param name="i"> power to be raised to. </param>
		/// <returns> int power i of f </returns>
		public static float floatPow(float f, int i) {
			float g = 1;

			for(; i > 0; i--) {
				g *= f;
			}

			return g;
		}

		/// <summary>
		///     calculate the logarithm to the base 2.
		/// </summary>
		/// <param name="x"> any double value </param>
		/// <returns> log_2(x) </returns>
		/// @deprecated use MathFunctions.log(double) instead
		public static double log(double x) {
			if((x > 0) && (x < 1)) {
				double d      = 1 / x;
				double result = -log(d);

				return result;
			}

			int    tmp  = 0;
			double tmp2 = 1;
			double d2   = x;

			while(d2 > 2) {
				d2   =  d2 / 2;
				tmp  += 1;
				tmp2 *= 2;
			}

			double rem = x / tmp2;
			rem = logBKM(rem);

			return tmp + rem;
		}

		/// <summary>
		///     calculate the logarithm to the base 2.
		/// </summary>
		/// <param name="x"> any long value &gt;=1 </param>
		/// <returns> log_2(x) </returns>
		/// @deprecated use MathFunctions.log(long) instead
		public static double log(long x) {
			int    tmp  = floorLog(BigInteger.ValueOf(x));
			long   tmp2 = 1 << tmp;
			double rem  = x / (double) tmp2;
			rem = logBKM(rem);

			return tmp + rem;
		}

		/// <summary>
		///     BKM Algorithm to calculate logarithms to the base 2.
		/// </summary>
		/// <param name="arg">
		///     a double value with 1<= arg<= 4.768462058 </param>
		/// <returns> log_2(arg) </returns>
		/// @deprecated use MathFunctions.logBKM(double) instead
		private static double logBKM(double arg) {
			double[] ae = {1.0000000000000000000000000000000000000000000000000000000000000000000000000000, 0.5849625007211561814537389439478165087598144076924810604557526545410982276485, 0.3219280948873623478703194294893901758648313930245806120547563958159347765589, 0.1699250014423123629074778878956330175196288153849621209115053090821964552970, 0.0874628412503394082540660108104043540112672823448206881266090643866965081686, 0.0443941193584534376531019906736094674630459333742491317685543002674288465967, 0.0223678130284545082671320837460849094932677948156179815932199216587899627785, 0.0112272554232541203378805844158839407281095943600297940811823651462712311786, 0.0056245491938781069198591026740666017211096815383520359072957784732489771013, 0.0028150156070540381547362547502839489729507927389771959487826944878598909400, 0.0014081943928083889066101665016890524233311715793462235597709051792834906001, 0.0007042690112466432585379340422201964456668872087249334581924550139514213168, 0.0003521774803010272377989609925281744988670304302127133979341729842842377649, 0.0001760994864425060348637509459678580940163670081839283659942864068257522373, 0.0000880524301221769086378699983597183301490534085738474534831071719854721939, 0.0000440268868273167176441087067175806394819146645511899503059774914593663365, 0.0000220136113603404964890728830697555571275493801909791504158295359319433723, 0.0000110068476674814423006223021573490183469930819844945565597452748333526464, 0.0000055034343306486037230640321058826431606183125807276574241540303833251704, 0.0000027517197895612831123023958331509538486493412831626219340570294203116559, 0.0000013758605508411382010566802834037147561973553922354232704569052932922954, 0.0000006879304394358496786728937442939160483304056131990916985043387874690617, 0.0000003439652607217645360118314743718005315334062644619363447395987584138324, 0.0000001719826406118446361936972479533123619972434705828085978955697643547921, 0.0000000859913228686632156462565208266682841603921494181830811515318381744650, 0.0000000429956620750168703982940244684787907148132725669106053076409624949917, 0.0000000214978311976797556164155504126645192380395989504741781512309853438587, 0.0000000107489156388827085092095702361647949603617203979413516082280717515504, 0.0000000053744578294520620044408178949217773318785601260677517784797554422804, 0.0000000026872289172287079490026152352638891824761667284401180026908031182361, 0.0000000013436144592400232123622589569799954658536700992739887706412976115422, 0.0000000006718072297764289157920422846078078155859484240808550018085324187007, 0.0000000003359036149273187853169587152657145221968468364663464125722491530858, 0.0000000001679518074734354745159899223037458278711244127245990591908996412262, 0.0000000000839759037391617577226571237484864917411614198675604731728132152582, 0.0000000000419879518701918839775296677020135040214077417929807824842667285938, 0.0000000000209939759352486932678195559552767641474249812845414125580747434389, 0.0000000000104969879676625344536740142096218372850561859495065136990936290929, 0.0000000000052484939838408141817781356260462777942148580518406975851213868092, 0.0000000000026242469919227938296243586262369156865545638305682553644113887909, 0.0000000000013121234959619935994960031017850191710121890821178731821983105443, 0.0000000000006560617479811459709189576337295395590603644549624717910616347038, 0.0000000000003280308739906102782522178545328259781415615142931952662153623493, 0.0000000000001640154369953144623242936888032768768777422997704541618141646683, 0.0000000000000820077184976595619616930350508356401599552034612281802599177300, 0.0000000000000410038592488303636807330652208397742314215159774270270147020117, 0.0000000000000205019296244153275153381695384157073687186580546938331088730952, 0.0000000000000102509648122077001764119940017243502120046885379813510430378661, 0.0000000000000051254824061038591928917243090559919209628584150482483994782302, 0.0000000000000025627412030519318726172939815845367496027046030028595094737777, 0.0000000000000012813706015259665053515049475574143952543145124550608158430592, 0.0000000000000006406853007629833949364669629701200556369782295210193569318434, 0.0000000000000003203426503814917330334121037829290364330169106716787999052925, 0.0000000000000001601713251907458754080007074659337446341494733882570243497196, 0.0000000000000000800856625953729399268240176265844257044861248416330071223615, 0.0000000000000000400428312976864705191179247866966320469710511619971334577509, 0.0000000000000000200214156488432353984854413866994246781519154793320684126179, 0.0000000000000000100107078244216177339743404416874899847406043033792202127070, 0.0000000000000000050053539122108088756700751579281894640362199287591340285355, 0.0000000000000000025026769561054044400057638132352058574658089256646014899499, 0.0000000000000000012513384780527022205455634651853807110362316427807660551208, 0.0000000000000000006256692390263511104084521222346348012116229213309001913762, 0.0000000000000000003128346195131755552381436585278035120438976487697544916191, 0.0000000000000000001564173097565877776275512286165232838833090480508502328437, 0.0000000000000000000782086548782938888158954641464170239072244145219054734086, 0.0000000000000000000391043274391469444084776945327473574450334092075712154016, 0.0000000000000000000195521637195734722043713378812583900953755962557525252782, 0.0000000000000000000097760818597867361022187915943503728909029699365320287407, 0.0000000000000000000048880409298933680511176764606054809062553340323879609794, 0.0000000000000000000024440204649466840255609083961603140683286362962192177597, 0.0000000000000000000012220102324733420127809717395445504379645613448652614939, 0.0000000000000000000006110051162366710063906152551383735699323415812152114058, 0.0000000000000000000003055025581183355031953399739107113727036860315024588989, 0.0000000000000000000001527512790591677515976780735407368332862218276873443537, 0.0000000000000000000000763756395295838757988410584167137033767056170417508383, 0.0000000000000000000000381878197647919378994210346199431733717514843471513618, 0.0000000000000000000000190939098823959689497106436628681671067254111334889005, 0.0000000000000000000000095469549411979844748553534196582286585751228071408728, 0.0000000000000000000000047734774705989922374276846068851506055906657137209047, 0.0000000000000000000000023867387352994961187138442777065843718711089344045782, 0.0000000000000000000000011933693676497480593569226324192944532044984865894525, 0.0000000000000000000000005966846838248740296784614396011477934194852481410926, 0.0000000000000000000000002983423419124370148392307506484490384140516252814304, 0.0000000000000000000000001491711709562185074196153830361933046331030629430117, 0.0000000000000000000000000745855854781092537098076934460888486730708440475045, 0.0000000000000000000000000372927927390546268549038472050424734256652501673274, 0.0000000000000000000000000186463963695273134274519237230207489851150821191330, 0.0000000000000000000000000093231981847636567137259618916352525606281553180093, 0.0000000000000000000000000046615990923818283568629809533488457973317312233323, 0.0000000000000000000000000023307995461909141784314904785572277779202790023236, 0.0000000000000000000000000011653997730954570892157452397493151087737428485431, 0.0000000000000000000000000005826998865477285446078726199923328593402722606924, 0.0000000000000000000000000002913499432738642723039363100255852559084863397344, 0.0000000000000000000000000001456749716369321361519681550201473345138307215067, 0.0000000000000000000000000000728374858184660680759840775119123438968122488047, 0.0000000000000000000000000000364187429092330340379920387564158411083803465567, 0.0000000000000000000000000000182093714546165170189960193783228378441837282509, 0.0000000000000000000000000000091046857273082585094980096891901482445902524441, 0.0000000000000000000000000000045523428636541292547490048446022564529197237262, 0.0000000000000000000000000000022761714318270646273745024223029238091160103901}; // A_e[k] = log_2 (1 + 0.5^k)
			int      n  = 53;
			double   x  = 1;
			double   y  = 0;
			double   z;
			double   s = 1;
			int      k;

			for(k = 0; k < n; k++) {
				z = x + (x * s);

				if(z <= arg) {
					x =  z;
					y += ae[k];
				}

				s *= 0.05;
			}

			return y;
		}

		public static bool isIncreasing(int[] a) {
			for(int i = 1; i < a.Length; i++) {
				if(a[i - 1] >= a[i]) {
					Console.WriteLine("a[" + (i - 1) + "] = " + a[i - 1] + " >= " + a[i] + " = a[" + i + "]");

					return false;
				}
			}

			return true;
		}

		public static SafeArrayHandle integerToOctets(BigInteger val) {
			using(SafeArrayHandle valBytes = val.Abs().ToByteArray()) {

				// check whether the array includes a sign bit
				if((val.BitLength & 7) != 0) {
					return valBytes;
				}

				// get rid of the sign bit (first byte)
				SafeArrayHandle tmp = SafeArrayHandle.Create(val.BitLength >> 3);
				tmp.Entry.CopyFrom(valBytes.Entry, 1, 0, tmp.Length);

				return tmp;

			}
		}

		public static BigInteger octetsToInteger(SafeArrayHandle data, int offset, int length) {
			using(SafeArrayHandle val = SafeArrayHandle.Create(length + 1)) {

				val[0] = 0;

				val.Entry.CopyFrom(data.Entry, offset, 1, length);

				return new BigInteger(val);

			}
		}

		public static BigInteger octetsToInteger(SafeArrayHandle data) {
			return octetsToInteger(data, 0, data.Length);
		}
	}

}
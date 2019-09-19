using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.euclid;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.util;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A polynomial with <code>int</code> coefficients.
	///     <br>
	///         Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
	///         not but return the result as a new polynomial.
	/// </summary>
	public class IntegerPolynomial : IPolynomial {
		private const int NUM_EQUAL_RESULTANTS = 3;

		/// <summary>
		///     Prime numbers &gt; 4500 for resultant computation. Starting them below ~4400 causes incorrect results occasionally.
		///     Fortunately, 4500 is about the optimum number for performance.<br />
		///     This array contains enough prime numbers so primes never have to be computed on-line for any standard
		///     <seealso cref="org.bouncycastle.pqc.crypto.ntru.NTRUSigningParameters" />.
		/// </summary>
		private static readonly int[] PRIMES = {4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973};

		private static readonly IList BIGINT_PRIMES;

		public int[] coeffs;

		static IntegerPolynomial() {
			BIGINT_PRIMES = new ArrayList();

			for(int i = 0; i != PRIMES.Length; i++) {
				BIGINT_PRIMES.Add(BigInteger.ValueOf(PRIMES[i]));
			}
		}

		/// <summary>
		///     Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
		/// </summary>
		/// <param name="N"> the number of coefficients </param>
		public IntegerPolynomial(int N) {
			this.coeffs = new int[N];
		}

		/// <summary>
		///     Constructs a new polynomial with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		public IntegerPolynomial(int[] coeffs) {
			this.coeffs = coeffs;
		}

		/// <summary>
		///     Constructs a <code>IntegerPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are
		///     independent of each other.
		/// </summary>
		/// <param name="p"> the original polynomial </param>
		public IntegerPolynomial(BigIntPolynomial p) {
			this.coeffs = new int[p.coeffs.Length];

			for(int i = 0; i < p.coeffs.Length; i++) {
				this.coeffs[i] = p.coeffs[i].ToInt32();
			}
		}

		/// <summary>
		///     Multiplies the polynomial with another, taking the values mod modulus and the indices mod N
		/// </summary>
		public virtual IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
			IntegerPolynomial c = this.mult(poly2);
			c.mod(modulus);

			return c;
		}

		/// <summary>
		///     Multiplies the polynomial with another, taking the indices mod N
		/// </summary>
		public virtual IntegerPolynomial mult(IntegerPolynomial poly2) {
			int N = this.coeffs.Length;

			if(poly2.coeffs.Length != N) {
				throw new ArgumentException("Number of coefficients must be the same");
			}

			IntegerPolynomial c = this.multRecursive(poly2);

			if(c.coeffs.Length > N) {
				for(int k = N; k < c.coeffs.Length; k++) {
					c.coeffs[k - N] += c.coeffs[k];
				}

				c.coeffs = Arrays.CopyOf(c.coeffs, N);
			}

			return c;
		}

		public virtual BigIntPolynomial mult(BigIntPolynomial poly2) {
			return new BigIntPolynomial(this).mult(poly2);
		}

		public virtual IntegerPolynomial toIntegerPolynomial() {
			return this.clone();
		}

		/// <summary>
		///     Decodes a byte array to a polynomial with <code>N</code> ternary coefficients
		///     <br>
		///         Ignores any excess bytes.
		/// </summary>
		/// <param name="data"> an encoded ternary polynomial </param>
		/// <param name="N">    number of coefficients </param>
		/// <returns> the decoded polynomial </returns>
		public static IntegerPolynomial fromBinary3Sves(SafeArrayHandle data, int N) {
			return new IntegerPolynomial(ArrayEncoder.decodeMod3Sves(data, N));
		}

		/// <summary>
		///     Converts a byte array produced by <seealso cref="#toBinary3Tight()" /> to a polynomial.
		/// </summary>
		/// <param name="b"> a byte array </param>
		/// <param name="N"> number of coefficients </param>
		/// <returns> the decoded polynomial </returns>
		public static IntegerPolynomial fromBinary3Tight(SafeArrayHandle b, int N) {
			return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(b, N));
		}

		/// <summary>
		///     Reads data produced by <seealso cref="#toBinary3Tight()" /> from an input stream and converts it to a polynomial.
		/// </summary>
		/// <param name="is"> an input stream </param>
		/// <param name="N">  number of coefficients </param>
		/// <returns> the decoded polynomial </returns>
		public static IntegerPolynomial fromBinary3Tight(MemoryStream InputStream, int N) {
			return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(InputStream, N));
		}

		/// <summary>
		///     Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.
		///     <br>
		///         <code>q</code> must be a power of 2.
		///         <br>
		///             Ignores any excess bytes.
		/// </summary>
		/// <param name="data"> an encoded ternary polynomial </param>
		/// <param name="N">    number of coefficients </param>
		/// <param name="q"> </param>
		/// <returns> the decoded polynomial </returns>
		public static IntegerPolynomial fromBinary(SafeArrayHandle data, int N, int q) {
			return new IntegerPolynomial(ArrayEncoder.decodeModQ(data, N, q));
		}

		/// <summary>
		///     Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.
		///     <br>
		///         <code>q</code> must be a power of 2.
		///         <br>
		///             Ignores any excess bytes.
		/// </summary>
		/// <param name="is"> an encoded ternary polynomial </param>
		/// <param name="N">  number of coefficients </param>
		/// <param name="q"> </param>
		/// <returns> the decoded polynomial </returns>
		public static IntegerPolynomial fromBinary(Stream @is, int N, int q) {
			return new IntegerPolynomial(ArrayEncoder.decodeModQ(@is, N, q));
		}

		/// <summary>
		///     Encodes a polynomial with ternary coefficients to binary.
		///     <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer <code>i</code>,
		///     so this method is only safe to use with polynomials produced by <code>fromBinary3Sves()</code>.
		/// </summary>
		/// <returns> the encoded polynomial </returns>
		public virtual SafeArrayHandle toBinary3Sves() {
			return ArrayEncoder.encodeMod3Sves(this.coeffs);
		}

		/// <summary>
		///     Converts a polynomial with ternary coefficients to binary.
		/// </summary>
		/// <returns> the encoded polynomial </returns>
		public virtual SafeArrayHandle toBinary3Tight() {
			return ArrayEncoder.encodeMod3Tight(this.coeffs);
		}

		/// <summary>
		///     Encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
		/// </summary>
		/// <param name="q"> </param>
		/// <returns> the encoded polynomial </returns>
		public virtual SafeArrayHandle toBinary(int q) {
			return ArrayEncoder.encodeModQ(this.coeffs, q);
		}

		/// <summary>
		///     Karazuba multiplication
		/// </summary>
		private IntegerPolynomial multRecursive(IntegerPolynomial poly2) {
			int[] a = this.coeffs;
			int[] b = poly2.coeffs;

			int n = poly2.coeffs.Length;

			if(n <= 32) {
				int               cn = (2 * n) - 1;
				IntegerPolynomial c  = new IntegerPolynomial(new int[cn]);

				for(int k = 0; k < cn; k++) {
					for(int i = Math.Max(0, (k - n) + 1); i <= Math.Min(k, n - 1); i++) {
						c.coeffs[k] += b[i] * a[k - i];
					}
				}

				return c;
			} else {
				int n1 = n / 2;

				IntegerPolynomial a1 = new IntegerPolynomial(Arrays.CopyOf(a, n1));
				IntegerPolynomial a2 = new IntegerPolynomial(Arrays.CopyOfRange(a, n1, n));
				IntegerPolynomial b1 = new IntegerPolynomial(Arrays.CopyOf(b, n1));
				IntegerPolynomial b2 = new IntegerPolynomial(Arrays.CopyOfRange(b, n1, n));

				IntegerPolynomial A = a1.clone();
				A.add(a2);
				IntegerPolynomial B = b1.clone();
				B.add(b2);

				IntegerPolynomial c1 = a1.multRecursive(b1);
				IntegerPolynomial c2 = a2.multRecursive(b2);
				IntegerPolynomial c3 = A.multRecursive(B);
				c3.sub(c1);
				c3.sub(c2);

				IntegerPolynomial c = new IntegerPolynomial((2 * n) - 1);

				for(int i = 0; i < c1.coeffs.Length; i++) {
					c.coeffs[i] = c1.coeffs[i];
				}

				for(int i = 0; i < c3.coeffs.Length; i++) {
					c.coeffs[n1 + i] += c3.coeffs[i];
				}

				for(int i = 0; i < c2.coeffs.Length; i++) {
					c.coeffs[(2 * n1) + i] += c2.coeffs[i];
				}

				return c;
			}
		}

		/// <summary>
		///     Computes the inverse mod <code>q; q</code> must be a power of 2.
		///     <br>
		///         Returns <code>null</code> if the polynomial is not invertible.
		/// </summary>
		/// <param name="q"> the modulus </param>
		/// <returns> a new polynomial </returns>
		public virtual IntegerPolynomial invertFq(int q) {
			int               N = this.coeffs.Length;
			int               k = 0;
			IntegerPolynomial b = new IntegerPolynomial(N + 1);
			b.coeffs[0] = 1;
			IntegerPolynomial c = new IntegerPolynomial(N + 1);
			IntegerPolynomial f = new IntegerPolynomial(N + 1);
			f.coeffs = Arrays.CopyOf(this.coeffs, N + 1);
			f.modPositive(2);

			// set g(x) = x^N − 1
			IntegerPolynomial g = new IntegerPolynomial(N + 1);
			g.coeffs[0] = 1;
			g.coeffs[N] = 1;

			while(true) {
				while(f.coeffs[0] == 0) {
					for(int i = 1; i <= N; i++) {
						f.coeffs[i       - 1] = f.coeffs[i];     // f(x) = f(x) / x
						c.coeffs[(N + 1) - i] = c.coeffs[N - i]; // c(x) = c(x) * x
					}

					f.coeffs[N] = 0;
					c.coeffs[0] = 0;
					k++;

					if(f.equalsZero()) {
						return null; // not invertible
					}
				}

				if(f.equalsOne()) {
					break;
				}

				if(f.degree() < g.degree()) {
					// exchange f and g
					IntegerPolynomial temp = f;
					f = g;
					g = temp;

					// exchange b and c
					temp = b;
					b    = c;
					c    = temp;
				}

				f.add(g, 2);
				b.add(c, 2);
			}

			if(b.coeffs[N] != 0) {
				return null;
			}

			// Fq(x) = x^(N-k) * b(x)
			IntegerPolynomial Fq = new IntegerPolynomial(N);
			int               j  = 0;
			k %= N;

			for(int i = N - 1; i >= 0; i--) {
				j = i - k;

				if(j < 0) {
					j += N;
				}

				Fq.coeffs[j] = b.coeffs[i];
			}

			return this.mod2ToModq(Fq, q);
		}

		/// <summary>
		///     Computes the inverse mod q from the inverse mod 2
		/// </summary>
		/// <param name="Fq"> </param>
		/// <param name="q"> </param>
		/// <returns> The inverse of this polynomial mod q </returns>
		private IntegerPolynomial mod2ToModq(IntegerPolynomial Fq, int q) {
			if(Util.Is64Bit() && (q == 2048)) {
				LongPolynomial2 thisLong = new LongPolynomial2(this);
				LongPolynomial2 FqLong   = new LongPolynomial2(Fq);
				int             v        = 2;

				while(v < q) {
					v *= 2;
					LongPolynomial2 temp = FqLong.Clone();
					temp.mult2And(v - 1);
					FqLong = thisLong.mult(FqLong).mult(FqLong);
					temp.subAnd(FqLong, v - 1);
					FqLong = temp;
				}

				return FqLong.toIntegerPolynomial();
			} else {
				int v = 2;

				while(v < q) {
					v *= 2;
					IntegerPolynomial temp = new IntegerPolynomial(Arrays.CopyOf(Fq.coeffs, Fq.coeffs.Length));
					temp.mult2(v);
					Fq = this.mult(Fq, v).mult(Fq, v);
					temp.sub(Fq, v);
					Fq = temp;
				}

				return Fq;
			}
		}

		/// <summary>
		///     Computes the inverse mod 3.
		///     Returns <code>null</code> if the polynomial is not invertible.
		/// </summary>
		/// <returns> a new polynomial </returns>
		public virtual IntegerPolynomial invertF3() {
			int               N = this.coeffs.Length;
			int               k = 0;
			IntegerPolynomial b = new IntegerPolynomial(N + 1);
			b.coeffs[0] = 1;
			IntegerPolynomial c = new IntegerPolynomial(N + 1);
			IntegerPolynomial f = new IntegerPolynomial(N + 1);
			f.coeffs = Arrays.CopyOf(this.coeffs, N + 1);
			f.modPositive(3);

			// set g(x) = x^N − 1
			IntegerPolynomial g = new IntegerPolynomial(N + 1);
			g.coeffs[0] = -1;
			g.coeffs[N] = 1;

			while(true) {
				while(f.coeffs[0] == 0) {
					for(int i = 1; i <= N; i++) {
						f.coeffs[i       - 1] = f.coeffs[i];     // f(x) = f(x) / x
						c.coeffs[(N + 1) - i] = c.coeffs[N - i]; // c(x) = c(x) * x
					}

					f.coeffs[N] = 0;
					c.coeffs[0] = 0;
					k++;

					if(f.equalsZero()) {
						return null; // not invertible
					}
				}

				if(f.equalsAbsOne()) {
					break;
				}

				if(f.degree() < g.degree()) {
					// exchange f and g
					IntegerPolynomial temp = f;
					f = g;
					g = temp;

					// exchange b and c
					temp = b;
					b    = c;
					c    = temp;
				}

				if(f.coeffs[0] == g.coeffs[0]) {
					f.sub(g, 3);
					b.sub(c, 3);
				} else {
					f.add(g, 3);
					b.add(c, 3);
				}
			}

			if(b.coeffs[N] != 0) {
				return null;
			}

			// Fp(x) = [+-] x^(N-k) * b(x)
			IntegerPolynomial Fp = new IntegerPolynomial(N);
			int               j  = 0;
			k %= N;

			for(int i = N - 1; i >= 0; i--) {
				j = i - k;

				if(j < 0) {
					j += N;
				}

				Fp.coeffs[j] = f.coeffs[0] * b.coeffs[i];
			}

			Fp.ensurePositive(3);

			return Fp;
		}

		/// <summary>
		///     Resultant of this polynomial with <code>x^n-1</code> using a probabilistic algorithm.
		///     <para>
		///         Unlike EESS, this implementation does not compute all resultants modulo primes
		///         such that their product exceeds the maximum possible resultant, but rather stops
		///         when <code>NUM_EQUAL_RESULTANTS</code> consecutive modular resultants are equal.
		///         <br>
		///             This means the return value may be incorrect. Experiments show this happens in
		///             about 1 out of 100 cases when <code>N=439</code> and <code>NUM_EQUAL_RESULTANTS=2</code>,
		///             so the likelyhood of leaving the loop too early is <code>(1/100)^(NUM_EQUAL_RESULTANTS-1)</code>.
		///     </para>
		///     <para>
		///         Because of the above, callers must verify the output and try a different polynomial if necessary.
		///     </para>
		/// </summary>
		/// <returns> <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>. </returns>
		public virtual Resultant resultant() {
			int N = this.coeffs.Length;

			// Compute resultants modulo prime numbers. Continue until NUM_EQUAL_RESULTANTS consecutive modular resultants are equal.
			LinkedList<ModularResultant> modResultants = new LinkedList<ModularResultant>();
			BigInteger                   pProd         = Constants.BIGINT_ONE;
			BigInteger                   pProd2        = null;
			BigInteger                   pProd2n       = null;
			BigInteger                   res           = Constants.BIGINT_ONE;
			int                          numEqual      = 1; // number of consecutive modular resultants equal to each other

			PrimeGenerator primes = new PrimeGenerator(this);

			while(true) {
				BigInteger       prime = primes.nextPrime();
				ModularResultant crr   = this.resultant(prime.ToInt32());
				modResultants.AddLast(crr);

				BigInteger      temp    = pProd.Multiply(prime);
				BigIntEuclidean er      = BigIntEuclidean.calculate(prime, pProd);
				BigInteger      resPrev = res;
				res = res.Multiply(er.x.Multiply(prime));

				BigInteger res2 = crr.res * er.y * pProd;
				res   = res.Add(res2).Mod(temp);
				pProd = temp;

				pProd2  = pProd.Divide(BigInteger.ValueOf(2));
				pProd2n = pProd2.Negate();

				if(res.CompareTo(pProd2) > 0) {
					res = res.Subtract(pProd);
				} else if(res.CompareTo(pProd2n) < 0) {
					res = res.Add(pProd);
				}

				if(res.Equals(resPrev)) {
					numEqual++;

					if(numEqual >= NUM_EQUAL_RESULTANTS) {
						break;
					}
				} else {
					numEqual = 1;
				}
			}

			// Combine modular rho's to obtain the final rho.
			// For efficiency, first combine all pairs of small resultants to bigger resultants,
			// then combine pairs of those, etc. until only one is left.
			while(modResultants.Count > 1) {
				ModularResultant modRes1 = modResultants.First.Value;
				modResultants.RemoveFirst();
				ModularResultant modRes2 = modResultants.First.Value;
				modResultants.RemoveFirst();
				ModularResultant modRes3 = ModularResultant.combineRho(modRes1, modRes2);
				modResultants.AddLast(modRes3);
			}

			BigIntPolynomial rhoP = modResultants.First.Value.rho;

			pProd2  = pProd / BigInteger.ValueOf(2);
			pProd2n = -pProd2;

			if(res.CompareTo(pProd2) > 0) {
				res = res - pProd;
			}

			if(res.CompareTo(pProd2n) < 0) {
				res = res + pProd;
			}

			for(int i = 0; i < N; i++) {
				BigInteger c = rhoP.coeffs[i];

				if(c.CompareTo(pProd2) > 0) {
					rhoP.coeffs[i] = c - pProd;
				}

				if(c.CompareTo(pProd2n) < 0) {
					rhoP.coeffs[i] = c + pProd;
				}
			}

			return new Resultant(rhoP, res);
		}

		/// <summary>
		///     Resultant of this polynomial with <code>x^n-1 mod p</code>.
		/// </summary>
		/// <returns>
		///     <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1) mod p</code> for some integer
		///     <code>t</code>.
		/// </returns>
		public virtual ModularResultant resultant(int p) {
			// Add a coefficient as the following operations involve polynomials of degree deg(f)+1
			int[]             fcoeffs = Arrays.CopyOf(this.coeffs, this.coeffs.Length + 1);
			IntegerPolynomial f       = new IntegerPolynomial(fcoeffs);
			int               N       = fcoeffs.Length;

			IntegerPolynomial a = new IntegerPolynomial(N);
			a.coeffs[0]     = -1;
			a.coeffs[N - 1] = 1;
			IntegerPolynomial b  = new IntegerPolynomial(f.coeffs);
			IntegerPolynomial v1 = new IntegerPolynomial(N);
			IntegerPolynomial v2 = new IntegerPolynomial(N);
			v2.coeffs[0] = 1;
			int da = N - 1;
			int db = b.degree();
			int ta = da;
			int c  = 0;
			int r  = 1;

			while(db > 0) {
				c = Util.invert(b.coeffs[db], p);
				c = (c * a.coeffs[da]) % p;
				a.multShiftSub(b, c, da   - db, p);
				v1.multShiftSub(v2, c, da - db, p);

				da = a.degree();

				if(da < db) {
					r *= Util.pow(b.coeffs[db], ta - da, p);
					r %= p;

					if(((ta % 2) == 1) && ((db % 2) == 1)) {
						r = -r % p;
					}

					IntegerPolynomial temp = a;
					a = b;
					b = temp;
					int tempdeg = da;
					da   = db;
					temp = v1;
					v1   = v2;
					v2   = temp;
					ta   = db;
					db   = tempdeg;
				}
			}

			r *= Util.pow(b.coeffs[0], da, p);
			r %= p;
			c =  Util.invert(b.coeffs[0], p);
			v2.mult(c);
			v2.mod(p);
			v2.mult(r);
			v2.mod(p);

			// drop the highest coefficient so #coeffs matches the original input
			v2.coeffs = Arrays.CopyOf(v2.coeffs, v2.coeffs.Length - 1);

			return new ModularResultant(new BigIntPolynomial(v2), BigInteger.ValueOf(r), BigInteger.ValueOf(p));
		}

		/// <summary>
		///     Computes <code>this-b*c*(x^k) mod p</code> and stores the result in this polynomial.<br />
		///     See steps 4a,4b in EESS algorithm 2.2.7.1.
		/// </summary>
		/// <param name="b"> </param>
		/// <param name="c"> </param>
		/// <param name="k"> </param>
		/// <param name="p"> </param>
		private void multShiftSub(IntegerPolynomial b, int c, int k, int p) {
			int N = this.coeffs.Length;

			for(int i = k; i < N; i++) {
				this.coeffs[i] = (this.coeffs[i] - (b.coeffs[i - k] * c)) % p;
			}
		}

		/// <summary>
		///     Adds the squares of all coefficients.
		/// </summary>
		/// <returns> the sum of squares </returns>
		private BigInteger squareSum() {
			BigInteger sum = Constants.BIGINT_ZERO;

			for(int i = 0; i < this.coeffs.Length; i++) {
				sum = sum + BigInteger.ValueOf(this.coeffs[i] * this.coeffs[i]);
			}

			return sum;
		}

		/// <summary>
		///     Returns the degree of the polynomial
		/// </summary>
		/// <returns> the degree </returns>
		internal virtual int degree() {
			int degree = this.coeffs.Length - 1;

			while((degree > 0) && (this.coeffs[degree] == 0)) {
				degree--;
			}

			return degree;
		}

		/// <summary>
		///     Adds another polynomial which can have a different number of coefficients,
		///     and takes the coefficient values mod <code>modulus</code>.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void add(IntegerPolynomial b, int modulus) {
			this.add(b);
			this.mod(modulus);
		}

		/// <summary>
		///     Adds another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void add(IntegerPolynomial b) {
			if(b.coeffs.Length > this.coeffs.Length) {
				this.coeffs = Arrays.CopyOf(this.coeffs, b.coeffs.Length);
			}

			for(int i = 0; i < b.coeffs.Length; i++) {
				this.coeffs[i] += b.coeffs[i];
			}
		}

		/// <summary>
		///     Subtracts another polynomial which can have a different number of coefficients,
		///     and takes the coefficient values mod <code>modulus</code>.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void sub(IntegerPolynomial b, int modulus) {
			this.sub(b);
			this.mod(modulus);
		}

		/// <summary>
		///     Subtracts another polynomial which can have a different number of coefficients.
		/// </summary>
		/// <param name="b"> another polynomial </param>
		public virtual void sub(IntegerPolynomial b) {
			if(b.coeffs.Length > this.coeffs.Length) {
				this.coeffs = Arrays.CopyOf(this.coeffs, b.coeffs.Length);
			}

			for(int i = 0; i < b.coeffs.Length; i++) {
				this.coeffs[i] -= b.coeffs[i];
			}
		}

		/// <summary>
		///     Subtracts a <code>int</code> from each coefficient. Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="b"> </param>
		internal virtual void sub(int b) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] -= b;
			}
		}

		/// <summary>
		///     Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
		/// </summary>
		/// <param name="factor"> </param>
		public virtual void mult(int factor) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] *= factor;
			}
		}

		/// <summary>
		///     Multiplies each coefficient by a 2 and applies a modulus. Does not return a new polynomial but modifies this
		///     polynomial.
		/// </summary>
		/// <param name="modulus"> a modulus </param>
		private void mult2(int modulus) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] *= 2;
				this.coeffs[i] %= modulus;
			}
		}

		/// <summary>
		///     Multiplies each coefficient by a 2 and applies a modulus. Does not return a new polynomial but modifies this
		///     polynomial.
		/// </summary>
		/// <param name="modulus"> a modulus </param>
		public virtual void mult3(int modulus) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] *= 3;
				this.coeffs[i] %= modulus;
			}
		}

		/// <summary>
		///     Divides each coefficient by <code>k</code> and rounds to the nearest integer. Does not return a new polynomial but
		///     modifies this polynomial.
		/// </summary>
		/// <param name="k"> the divisor </param>
		public virtual void div(int k) {
			int k2 = (k + 1) / 2;

			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] += this.coeffs[i] > 0 ? k2 : -k2;
				this.coeffs[i] /= k;
			}
		}

		/// <summary>
		///     Takes each coefficient modulo 3 such that all coefficients are ternary.
		/// </summary>
		public virtual void mod3() {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] %= 3;

				if(this.coeffs[i] > 1) {
					this.coeffs[i] -= 3;
				}

				if(this.coeffs[i] < -1) {
					this.coeffs[i] += 3;
				}
			}
		}

		/// <summary>
		///     Ensures all coefficients are between 0 and <code>modulus-1</code>
		/// </summary>
		/// <param name="modulus"> a modulus </param>
		public virtual void modPositive(int modulus) {
			this.mod(modulus);
			this.ensurePositive(modulus);
		}

		/// <summary>
		///     Reduces all coefficients to the interval [-modulus/2, modulus/2)
		/// </summary>
		internal virtual void modCenter(int modulus) {
			this.mod(modulus);

			for(int j = 0; j < this.coeffs.Length; j++) {
				while(this.coeffs[j] < (modulus / 2)) {
					this.coeffs[j] += modulus;
				}

				while(this.coeffs[j] >= (modulus / 2)) {
					this.coeffs[j] -= modulus;
				}
			}
		}

		/// <summary>
		///     Takes each coefficient modulo <code>modulus</code>.
		/// </summary>
		public virtual void mod(int modulus) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] %= modulus;
			}
		}

		/// <summary>
		///     Adds <code>modulus</code> until all coefficients are above 0.
		/// </summary>
		/// <param name="modulus"> a modulus </param>
		public virtual void ensurePositive(int modulus) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				while(this.coeffs[i] < 0) {
					this.coeffs[i] += modulus;
				}
			}
		}

		/// <summary>
		///     Computes the centered euclidean norm of the polynomial.
		/// </summary>
		/// <param name="q"> a modulus </param>
		/// <returns> the centered norm </returns>
		public virtual long centeredNormSq(int q) {
			int               N = this.coeffs.Length;
			IntegerPolynomial p = this.clone();
			p.shiftGap(q);

			long sum   = 0;
			long sqSum = 0;

			for(int i = 0; i != p.coeffs.Length; i++) {
				int c = p.coeffs[i];
				sum   += c;
				sqSum += c * c;
			}

			long centeredNormSq = sqSum - ((sum * sum) / N);

			return centeredNormSq;
		}

		/// <summary>
		///     Shifts all coefficients so the largest gap is centered around <code>-q/2</code>.
		/// </summary>
		/// <param name="q"> a modulus </param>
		internal virtual void shiftGap(int q) {
			this.modCenter(q);

			int[] sorted = Arrays.Clone(this.coeffs);

			this.sort(sorted);

			int maxrange      = 0;
			int maxrangeStart = 0;

			for(int i = 0; i < (sorted.Length - 1); i++) {
				int range = sorted[i + 1] - sorted[i];

				if(range > maxrange) {
					maxrange      = range;
					maxrangeStart = sorted[i];
				}
			}

			int pmin = sorted[0];
			int pmax = sorted[sorted.Length - 1];

			int j = (q - pmax) + pmin;
			int shift;

			if(j > maxrange) {
				shift = (pmax + pmin) / 2;
			} else {
				shift = maxrangeStart + (maxrange / 2) + (q / 2);
			}

			this.sub(shift);
		}

		private void sort(int[] ints) {
			bool swap = true;

			while(swap) {
				swap = false;

				for(int i = 0; i != (ints.Length - 1); i++) {
					if(ints[i] > ints[i + 1]) {
						int tmp = ints[i];
						ints[i] = ints[i + 1];
						ints[i           + 1] = tmp;
						swap                  = true;
					}
				}
			}
		}

		/// <summary>
		///     Shifts the values of all coefficients to the interval <code>[-q/2, q/2]</code>.
		/// </summary>
		/// <param name="q"> a modulus </param>
		public virtual void center0(int q) {
			for(int i = 0; i < this.coeffs.Length; i++) {
				while(this.coeffs[i] < (-q / 2)) {
					this.coeffs[i] += q;
				}

				while(this.coeffs[i] > (q / 2)) {
					this.coeffs[i] -= q;
				}
			}
		}

		/// <summary>
		///     Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
		/// </summary>
		/// <returns> the sum of all coefficients </returns>
		public virtual int sumCoeffs() {
			int sum = 0;

			for(int i = 0; i < this.coeffs.Length; i++) {
				sum += this.coeffs[i];
			}

			return sum;
		}

		/// <summary>
		///     Tests if <code>p(x) = 0</code>.
		/// </summary>
		/// <returns> true iff all coefficients are zeros </returns>
		private bool equalsZero() {
			for(int i = 0; i < this.coeffs.Length; i++) {
				if(this.coeffs[i] != 0) {
					return false;
				}
			}

			return true;
		}

		/// <summary>
		///     Tests if <code>p(x) = 1</code>.
		/// </summary>
		/// <returns> true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 </returns>
		public virtual bool equalsOne() {
			for(int i = 1; i < this.coeffs.Length; i++) {
				if(this.coeffs[i] != 0) {
					return false;
				}
			}

			return this.coeffs[0] == 1;
		}

		/// <summary>
		///     Tests if <code>|p(x)| = 1</code>.
		/// </summary>
		/// <returns> true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 or -1 </returns>
		private bool equalsAbsOne() {
			for(int i = 1; i < this.coeffs.Length; i++) {
				if(this.coeffs[i] != 0) {
					return false;
				}
			}

			return Math.Abs(this.coeffs[0]) == 1;
		}

		/// <summary>
		///     Counts the number of coefficients equal to an integer
		/// </summary>
		/// <param name="value"> an integer </param>
		/// <returns> the number of coefficients equal to <code>value</code> </returns>
		public virtual int count(int value) {
			int count = 0;

			for(int i = 0; i != this.coeffs.Length; i++) {
				if(this.coeffs[i] == value) {
					count++;
				}
			}

			return count;
		}

		/// <summary>
		///     Multiplication by <code>X</code> in <code>Z[X]/Z[X^n-1]</code>.
		/// </summary>
		public virtual void rotate1() {
			int clast = this.coeffs[this.coeffs.Length - 1];

			for(int i = this.coeffs.Length - 1; i > 0; i--) {
				this.coeffs[i] = this.coeffs[i - 1];
			}

			this.coeffs[0] = clast;
		}

		public virtual void clear() {
			for(int i = 0; i < this.coeffs.Length; i++) {
				this.coeffs[i] = 0;
			}
		}

		public virtual IntegerPolynomial clone() {
			return new IntegerPolynomial((int[]) this.coeffs.Clone());
		}

		public override bool Equals(object obj) {
			if(obj is IntegerPolynomial) {
				return Arrays.AreEqual(this.coeffs, ((IntegerPolynomial) obj).coeffs);
			}

			return false;
		}

		private class PrimeGenerator {
			private readonly IntegerPolynomial outerInstance;

			internal int        index;
			internal BigInteger prime;

			public PrimeGenerator(IntegerPolynomial outerInstance) {
				this.outerInstance = outerInstance;
			}

			public virtual BigInteger nextPrime() {
				if(this.index < BIGINT_PRIMES.Count) {
					this.prime = (BigInteger) BIGINT_PRIMES[this.index++];
				} else {
					this.prime = this.prime.NextProbablePrime();
				}

				return this.prime;
			}
		}
	}

}
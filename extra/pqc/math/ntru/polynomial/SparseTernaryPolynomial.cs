using System;
using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.util;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A <code>TernaryPolynomial</code> with a "low" number of nonzero coefficients.
	/// </summary>
	public class SparseTernaryPolynomial : TernaryPolynomial {
		/// <summary>
		///     Number of bits to use for each coefficient. Determines the upper bound for <code>N</code>.
		/// </summary>
		private const int BITS_PER_INDEX = 11;

		private readonly int   N;
		private readonly int[] negOnes;
		private readonly int[] ones;

		/// <summary>
		///     Constructs a new polynomial.
		/// </summary>
		/// <param name="N">       total number of coefficients including zeros </param>
		/// <param name="ones">    indices of coefficients equal to 1 </param>
		/// <param name="negOnes"> indices of coefficients equal to -1 </param>
		internal SparseTernaryPolynomial(int N, int[] ones, int[] negOnes) {
			this.N       = N;
			this.ones    = ones;
			this.negOnes = negOnes;
		}

		/// <summary>
		///     Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		///     independent of each other.
		/// </summary>
		/// <param name="intPoly"> the original polynomial </param>
		public SparseTernaryPolynomial(IntegerPolynomial intPoly) : this(intPoly.coeffs) {
		}

		/// <summary>
		///     Constructs a new <code>SparseTernaryPolynomial</code> with a given set of coefficients.
		/// </summary>
		/// <param name="coeffs"> the coefficients </param>
		public SparseTernaryPolynomial(int[] coeffs) {
			this.N       = coeffs.Length;
			this.ones    = new int[this.N];
			this.negOnes = new int[this.N];
			int onesIdx    = 0;
			int negOnesIdx = 0;

			for(int i = 0; i < this.N; i++) {
				int c = coeffs[i];

				switch(c) {
					case 1:
						this.ones[onesIdx++] = i;

						break;
					case -1:
						this.negOnes[negOnesIdx++] = i;

						break;
					case 0:

						break;
					default:

						throw new ArgumentException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
				}
			}

			this.ones    = Arrays.CopyOf(this.ones, onesIdx);
			this.negOnes = Arrays.CopyOf(this.negOnes, negOnesIdx);
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial poly2) {
			int[] b = poly2.coeffs;

			if(b.Length != this.N) {
				throw new ArgumentException("Number of coefficients must be the same");
			}

			int[] c = new int[this.N];

			for(int idx = 0; idx != this.ones.Length; idx++) {
				int i = this.ones[idx];
				int j = this.N - 1 - i;

				for(int k = this.N - 1; k >= 0; k--) {
					c[k] += b[j];
					j--;

					if(j < 0) {
						j = this.N - 1;
					}
				}
			}

			for(int idx = 0; idx != this.negOnes.Length; idx++) {
				int i = this.negOnes[idx];
				int j = this.N - 1 - i;

				for(int k = this.N - 1; k >= 0; k--) {
					c[k] -= b[j];
					j--;

					if(j < 0) {
						j = this.N - 1;
					}
				}
			}

			return new IntegerPolynomial(c);
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
			IntegerPolynomial c = this.mult(poly2);
			c.mod(modulus);

			return c;
		}

		public virtual BigIntPolynomial mult(BigIntPolynomial poly2) {
			BigInteger[] b = poly2.coeffs;

			if(b.Length != this.N) {
				throw new ArgumentException("Number of coefficients must be the same");
			}

			BigInteger[] c = new BigInteger[this.N];

			for(int i = 0; i < this.N; i++) {
				c[i] = BigInteger.Zero;
			}

			for(int idx = 0; idx != this.ones.Length; idx++) {
				int i = this.ones[idx];
				int j = this.N - 1 - i;

				for(int k = this.N - 1; k >= 0; k--) {
					c[k] = c[k].Add(b[j]);
					j--;

					if(j < 0) {
						j = this.N - 1;
					}
				}
			}

			for(int idx = 0; idx != this.negOnes.Length; idx++) {
				int i = this.negOnes[idx];
				int j = this.N - 1 - i;

				for(int k = this.N - 1; k >= 0; k--) {
					c[k] = c[k].Subtract(b[j]);
					j--;

					if(j < 0) {
						j = this.N - 1;
					}
				}
			}

			return new BigIntPolynomial(c);
		}

		public virtual int[] Ones => this.ones;

		public virtual int[] NegOnes => this.negOnes;

		public virtual IntegerPolynomial toIntegerPolynomial() {
			int[] coeffs = new int[this.N];

			for(int idx = 0; idx != this.ones.Length; idx++) {
				int i = this.ones[idx];
				coeffs[i] = 1;
			}

			for(int idx = 0; idx != this.negOnes.Length; idx++) {
				int i = this.negOnes[idx];
				coeffs[i] = -1;
			}

			return new IntegerPolynomial(coeffs);
		}

		public virtual int size() {
			return this.N;
		}

		public virtual void clear() {
			for(int i = 0; i < this.ones.Length; i++) {
				this.ones[i] = 0;
			}

			for(int i = 0; i < this.negOnes.Length; i++) {
				this.negOnes[i] = 0;
			}
		}

		/// <summary>
		///     Decodes a byte array encoded with <seealso cref="#toBinary()" /> to a ploynomial.
		/// </summary>
		/// <param name="is">         an input stream containing an encoded polynomial </param>
		/// <param name="N">          number of coefficients including zeros </param>
		/// <param name="numOnes">    number of coefficients equal to 1 </param>
		/// <param name="numNegOnes"> number of coefficients equal to -1 </param>
		/// <returns> the decoded polynomial </returns>
		/// <exception cref="IOException"> </exception>
		public static SparseTernaryPolynomial fromBinary(Stream @is, int N, int numOnes, int numNegOnes) {
			int maxIndex     = 1 << BITS_PER_INDEX;
			int bitsPerIndex = 32 - Extensions.NumberOfLeadingZeros(maxIndex - 1);

			int        data1Len = ((numOnes * bitsPerIndex) + 7) / 8;
			IByteArray data1    = Util.readFullLength(@is, data1Len);
			int[]      ones     = ArrayEncoder.decodeModQ(data1, numOnes, maxIndex);

			data1.Return();

			int        data2Len = ((numNegOnes * bitsPerIndex) + 7) / 8;
			IByteArray data2    = Util.readFullLength(@is, data2Len);
			int[]      negOnes  = ArrayEncoder.decodeModQ(data2, numNegOnes, maxIndex);

			data2.Return();

			return new SparseTernaryPolynomial(N, ones, negOnes);
		}

		/// <summary>
		///     Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
		///     <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N">          number of coefficients </param>
		/// <param name="numOnes">    number of 1's </param>
		/// <param name="numNegOnes"> number of -1's </param>
		public static SparseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes, SecureRandom random) {
			int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes, random);

			return new SparseTernaryPolynomial(coeffs);
		}

		/// <summary>
		///     Encodes the polynomial to a byte array writing <code>BITS_PER_INDEX</code> bits for each coefficient.
		/// </summary>
		/// <returns> the encoded polynomial </returns>
		public virtual IByteArray toBinary() {
			int        maxIndex = 1 << BITS_PER_INDEX;
			IByteArray bin1     = ArrayEncoder.encodeModQ(this.ones, maxIndex);
			IByteArray bin2     = ArrayEncoder.encodeModQ(this.negOnes, maxIndex);

			IByteArray bin = FastArrays.CopyOf(bin1, bin1.Length + bin2.Length);
			bin.CopyFrom(bin2, 0, bin1.Length, bin2.Length);

			bin1.Return();
			bin2.Return();

			return bin;
		}

		public override int GetHashCode() {
			const int prime  = 31;
			int       result = 1;
			result = (prime * result) + this.N;
			result = (prime * result) + Arrays.GetHashCode(this.negOnes);
			result = (prime * result) + Arrays.GetHashCode(this.ones);

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

			SparseTernaryPolynomial other = (SparseTernaryPolynomial) obj;

			if(this.N != other.N) {
				return false;
			}

			if(!Arrays.AreEqual(this.negOnes, other.negOnes)) {
				return false;
			}

			if(!Arrays.AreEqual(this.ones, other.ones)) {
				return false;
			}

			return true;
		}
	}

}
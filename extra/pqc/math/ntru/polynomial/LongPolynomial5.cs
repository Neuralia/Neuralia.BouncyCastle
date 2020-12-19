using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A polynomial class that combines five coefficients into one <code>long</code> value for
	///     faster multiplication by a ternary polynomial.
	///     <br>
	///         Coefficients can be between 0 and 2047 and are stored in bits 0..11, 12..23, ..., 48..59 of a <code>long</code>
	///         number.
	/// </summary>
	public class LongPolynomial5 {
		private readonly long[] coeffs; // groups of 5 coefficients
		private readonly int    numCoeffs;

		/// <summary>
		///     Constructs a <code>LongPolynomial5</code> from a <code>IntegerPolynomial</code>. The two polynomials are
		///     independent of each other.
		/// </summary>
		/// <param name="p"> the original polynomial. Coefficients must be between 0 and 2047. </param>
		public LongPolynomial5(IntegerPolynomial p) {
			this.numCoeffs = p.coeffs.Length;

			this.coeffs = new long[(this.numCoeffs + 4) / 5];
			int cIdx  = 0;
			int shift = 0;

			for(int i = 0; i < this.numCoeffs; i++) {
				this.coeffs[cIdx] |= (long) p.coeffs[i] << shift;
				shift             += 12;

				if(shift >= 60) {
					shift = 0;
					cIdx++;
				}
			}
		}

		private LongPolynomial5(long[] coeffs, int numCoeffs) {
			this.coeffs    = coeffs;
			this.numCoeffs = numCoeffs;
		}

		/// <summary>
		///     Multiplies the polynomial with a <code>TernaryPolynomial</code>, taking the indices mod N and the values mod 2048.
		/// </summary>
		public virtual LongPolynomial5 mult(TernaryPolynomial poly2) {

			long[][] prod = SquareArrays.ReturnRectangularLongArray(5, (this.coeffs.Length + ((poly2.size() + 4) / 5)) - 1); // intermediate results, the subarrays are shifted by 0,...,4 coefficients

			// multiply ones
			int[] ones = poly2.Ones;

			for(int idx = 0; idx != ones.Length; idx++) {
				int pIdx = ones[idx];
				int cIdx = pIdx / 5;
				int m    = pIdx - (cIdx * 5); // m = pIdx % 5

				for(int i = 0; i < this.coeffs.Length; i++) {
					prod[m][cIdx] = (prod[m][cIdx] + this.coeffs[i]) & 0x7FF7FF7FF7FF7FFL;
					cIdx++;
				}
			}

			// multiply negative ones
			int[] negOnes = poly2.NegOnes;

			for(int idx = 0; idx != negOnes.Length; idx++) {
				int pIdx = negOnes[idx];
				int cIdx = pIdx / 5;
				int m    = pIdx - (cIdx * 5); // m = pIdx % 5

				for(int i = 0; i < this.coeffs.Length; i++) {
					prod[m][cIdx] = ((0x800800800800800L + prod[m][cIdx]) - this.coeffs[i]) & 0x7FF7FF7FF7FF7FFL;
					cIdx++;
				}
			}

			// combine shifted coefficients (5 arrays) into a single array of length prod[*].length+1
			long[] cCoeffs = Arrays.CopyOf(prod[0], prod[0].Length + 1);

			for(int m = 1; m <= 4; m++) {
				int  shift   = m * 12;
				int  shift60 = 60              - shift;
				long mask    = (1L << shift60) - 1;
				int  pLen    = prod[m].Length;

				for(int i = 0; i < pLen; i++) {
					long upper, lower;
					upper = prod[m][i] >> shift60;
					lower = prod[m][i] & mask;

					cCoeffs[i] = (cCoeffs[i]             + (lower << shift)) & 0x7FF7FF7FF7FF7FFL;
					int nextIdx = i                      + 1;
					cCoeffs[nextIdx] = (cCoeffs[nextIdx] + upper) & 0x7FF7FF7FF7FF7FFL;
				}
			}

			// reduce indices of cCoeffs modulo numCoeffs
			int shift2 = 12 * (this.numCoeffs % 5);

			for(int cIdx = this.coeffs.Length - 1; cIdx < cCoeffs.Length; cIdx++) {
				long iCoeff; // coefficient to shift into the [0..numCoeffs-1] range
				int  newIdx;

				if(cIdx == (this.coeffs.Length - 1)) {
					iCoeff = this.numCoeffs == 5 ? 0 : cCoeffs[cIdx] >> shift2;
					newIdx = 0;
				} else {
					iCoeff = cCoeffs[cIdx];
					newIdx = (cIdx * 5) - this.numCoeffs;
				}

				int  @base = newIdx / 5;
				int  m     = newIdx - (@base * 5); // m = newIdx % 5
				long lower = iCoeff << (12   * m);
				long upper = iCoeff >> (12   * (5 - m));
				cCoeffs[@base] = (cCoeffs[@base] + lower) & 0x7FF7FF7FF7FF7FFL;
				int base1 = @base                + 1;

				if(base1 < this.coeffs.Length) {
					cCoeffs[base1] = (cCoeffs[base1] + upper) & 0x7FF7FF7FF7FF7FFL;
				}
			}

			return new LongPolynomial5(cCoeffs, this.numCoeffs);
		}

		public virtual IntegerPolynomial toIntegerPolynomial() {
			int[] intCoeffs = new int[this.numCoeffs];
			int   cIdx      = 0;
			int   shift     = 0;

			for(int i = 0; i < this.numCoeffs; i++) {
				intCoeffs[i] =  (int) ((this.coeffs[cIdx] >> shift) & 2047);
				shift        += 12;

				if(shift >= 60) {
					shift = 0;
					cIdx++;
				}
			}

			return new IntegerPolynomial(intCoeffs);
		}
	}

}
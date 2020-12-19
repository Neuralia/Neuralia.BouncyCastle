using System;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	/// <summary>
	///     This class represents polynomial rings <tt>GF(2^m)[X]/p(X)</tt> for
	///     <tt>m&lt;32</tt>. If <tt>p(X)</tt> is irreducible, the polynomial ring
	///     is in fact an extension field of <tt>GF(2^m)</tt>.
	/// </summary>
	public class PolynomialRingGF2m {

		/// <summary>
		///     the finite field this polynomial ring is defined over
		/// </summary>
		private readonly GF2mField field;

		/// <summary>
		///     the reduction polynomial
		/// </summary>
		private readonly PolynomialGF2mSmallM p;

		/// <summary>
		///     the squaring matrix for this polynomial ring (given as the array of its
		///     row vectors)
		/// </summary>
		protected internal PolynomialGF2mSmallM[] sqMatrix;

		/// <summary>
		///     the matrix for computing square roots in this polynomial ring (given as
		///     the array of its row vectors). This matrix is computed as the inverse of
		///     the squaring matrix.
		/// </summary>
		protected internal PolynomialGF2mSmallM[] sqRootMatrix;

		/// <summary>
		///     Constructor.
		/// </summary>
		/// <param name="field"> the finite field </param>
		/// <param name="p">     the reduction polynomial </param>
		public PolynomialRingGF2m(GF2mField field, PolynomialGF2mSmallM p) {
			this.field = field;
			this.p     = p;
			this.computeSquaringMatrix();
			this.computeSquareRootMatrix();
		}

		/// <returns> the squaring matrix for this polynomial ring </returns>
		public virtual PolynomialGF2mSmallM[] SquaringMatrix => this.sqMatrix;

		/// <returns> the matrix for computing square roots for this polynomial ring </returns>
		public virtual PolynomialGF2mSmallM[] SquareRootMatrix => this.sqRootMatrix;

		/// <summary>
		///     Compute the squaring matrix for this polynomial ring, using the base
		///     field and the reduction polynomial.
		/// </summary>
		private void computeSquaringMatrix() {
			int numColumns = this.p.Degree;
			this.sqMatrix = new PolynomialGF2mSmallM[numColumns];

			for(int i = 0; i < (numColumns >> 1); i++) {
				int[] monomCoeffs = new int[(i << 1) + 1];
				monomCoeffs[i << 1] = 1;
				this.sqMatrix[i]    = new PolynomialGF2mSmallM(this.field, monomCoeffs);
			}

			for(int i = numColumns >> 1; i < numColumns; i++) {
				int[] monomCoeffs = new int[(i << 1) + 1];
				monomCoeffs[i << 1] = 1;
				PolynomialGF2mSmallM monomial = new PolynomialGF2mSmallM(this.field, monomCoeffs);
				this.sqMatrix[i] = monomial.mod(this.p);
			}
		}

		/// <summary>
		///     Compute the matrix for computing square roots in this polynomial ring by
		///     inverting the squaring matrix.
		/// </summary>
		private void computeSquareRootMatrix() {
			int numColumns = this.p.Degree;

			// clone squaring matrix
			PolynomialGF2mSmallM[] tmpMatrix = new PolynomialGF2mSmallM[numColumns];

			for(int i = numColumns - 1; i >= 0; i--) {
				tmpMatrix[i] = new PolynomialGF2mSmallM(this.sqMatrix[i]);
			}

			// initialize square root matrix as unit matrix
			this.sqRootMatrix = new PolynomialGF2mSmallM[numColumns];

			for(int i = numColumns - 1; i >= 0; i--) {
				this.sqRootMatrix[i] = new PolynomialGF2mSmallM(this.field, i);
			}

			// simultaneously compute Gaussian reduction of squaring matrix and unit
			// matrix
			for(int i = 0; i < numColumns; i++) {
				// if diagonal element is zero
				if(tmpMatrix[i].getCoefficient(i) == 0) {
					bool foundNonZero = false;

					// find a non-zero element in the same row
					for(int j = i + 1; j < numColumns; j++) {
						if(tmpMatrix[j].getCoefficient(i) != 0) {
							// found it, swap columns ...
							foundNonZero = true;
							swapColumns(tmpMatrix, i, j);
							swapColumns(this.sqRootMatrix, i, j);

							// ... and quit searching
							j = numColumns;
						}
					}

					// if no non-zero element was found
					if(!foundNonZero) {
						// the matrix is not invertible
						throw new ArithmeticException("Squaring matrix is not invertible.");
					}
				}

				// normalize i-th column
				int coef    = tmpMatrix[i].getCoefficient(i);
				int invCoef = this.field.inverse(coef);
				tmpMatrix[i].multThisWithElement(invCoef);
				this.sqRootMatrix[i].multThisWithElement(invCoef);

				// normalize all other columns
				for(int j = 0; j < numColumns; j++) {
					if(j != i) {
						coef = tmpMatrix[j].getCoefficient(i);

						if(coef != 0) {
							PolynomialGF2mSmallM tmpSqColumn  = tmpMatrix[i].multWithElement(coef);
							PolynomialGF2mSmallM tmpInvColumn = this.sqRootMatrix[i].multWithElement(coef);
							tmpMatrix[j].addToThis(tmpSqColumn);
							this.sqRootMatrix[j].addToThis(tmpInvColumn);
						}
					}
				}
			}
		}

		private static void swapColumns(PolynomialGF2mSmallM[] matrix, int first, int second) {
			PolynomialGF2mSmallM tmp = matrix[first];
			matrix[first]  = matrix[second];
			matrix[second] = tmp;
		}
	}

}
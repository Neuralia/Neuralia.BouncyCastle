using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	/// <summary>
	///     This class describes some operations with matrices over finite field <i>GF(2<sup>m</sup>)</i>
	///     with small <i>m</i> (1&lt; m &lt;32).
	/// </summary>
	/// <seealso cref= Matrix
	/// </seealso>
	public class GF2mMatrix : Matrix {

		/// <summary>
		///     finite field GF(2^m)
		/// </summary>
		protected internal GF2mField field;

		/// <summary>
		///     For the matrix representation the array of type int[][] is used, thus
		///     every element of the array keeps one element of the matrix (element from
		///     finite field GF(2^m))
		/// </summary>
		protected internal int[][] matrix;

		/// <summary>
		///     Constructor.
		/// </summary>
		/// <param name="field"> a finite field GF(2^m) </param>
		/// <param name="enc">   ArrayWrapper matrix in byte array form </param>
		public GF2mMatrix(GF2mField field, SafeArrayHandle enc) {

			this.field = field;

			// decode matrix
			int d     = 8;
			int count = 1;

			while(field.Degree > d) {
				count++;
				d += 8;
			}

			if(enc.Length < 5) {
				throw new ArgumentException(" Error: given array is not encoded matrix over GF(2^m)");
			}

			this.numRows = ((enc[3] & 0xff) << 24) ^ ((enc[2] & 0xff) << 16) ^ ((enc[1] & 0xff) << 8) ^ (enc[0] & 0xff);

			int n = count * this.numRows;

			if((this.numRows <= 0) || (((enc.Length - 4) % n) != 0)) {
				throw new ArgumentException(" Error: given array is not encoded matrix over GF(2^m)");
			}

			this.numColumns = (enc.Length - 4) / n;

			this.matrix = SquareArrays.ReturnRectangularIntArray(this.numRows, this.numColumns);
			count       = 4;

			for(int i = 0; i < this.numRows; i++) {
				for(int j = 0; j < this.numColumns; j++) {
					for(int jj = 0; jj < d; jj += 8) {
						this.matrix[i][j] ^= (enc[count++] & 0x000000ff) << jj;
					}

					if(!this.field.isElementOfThisField(this.matrix[i][j])) {
						throw new ArgumentException(" Error: given array is not encoded matrix over GF(2^m)");
					}
				}
			}
		}

		/// <summary>
		///     Copy constructor.
		/// </summary>
		/// <param name="other"> another <seealso cref="GF2mMatrix" /> </param>
		public GF2mMatrix(GF2mMatrix other) {
			this.numRows    = other.numRows;
			this.numColumns = other.numColumns;
			this.field      = other.field;
			this.matrix     = new int[this.numRows][];

			for(int i = 0; i < this.numRows; i++) {
				this.matrix[i] = IntUtils.clone(other.matrix[i]);
			}
		}

		/// <summary>
		///     Constructor.
		/// </summary>
		/// <param name="field">  a finite field GF(2^m) </param>
		/// <param name="matrix"> the matrix as int array. Only the reference is copied. </param>
		protected internal GF2mMatrix(GF2mField field, int[][] matrix) {
			this.field      = field;
			this.matrix     = matrix;
			this.numRows    = matrix.Length;
			this.numColumns = matrix[0].Length;
		}

		/// <returns> a byte array encoding of this matrix </returns>
		public override SafeArrayHandle Encoded {
			get {
				int d     = 8;
				int count = 1;

				while(this.field.Degree > d) {
					count++;
					d += 8;
				}

				SafeArrayHandle bf = SafeArrayHandle.Create((this.numRows * this.numColumns * count) + 4);
				bf[0] = unchecked((byte) (this.numRows                      & 0xff));
				bf[1] = unchecked((byte) ((int) ((uint) this.numRows >> 8)  & 0xff));
				bf[2] = unchecked((byte) ((int) ((uint) this.numRows >> 16) & 0xff));
				bf[3] = unchecked((byte) ((int) ((uint) this.numRows >> 24) & 0xff));

				count = 4;

				for(int i = 0; i < this.numRows; i++) {
					for(int j = 0; j < this.numColumns; j++) {
						for(int jj = 0; jj < d; jj += 8) {
							bf[count++] = (byte) (int) ((uint) this.matrix[i][j] >> jj);
						}
					}
				}

				return bf;
			}
		}

		/// <summary>
		///     Check if this is the zero matrix (i.e., all entries are zero).
		/// </summary>
		/// <returns> <tt>true</tt> if this is the zero matrix </returns>
		public override bool Zero {
			get {
				for(int i = 0; i < this.numRows; i++) {
					for(int j = 0; j < this.numColumns; j++) {
						if(this.matrix[i][j] != 0) {
							return false;
						}
					}
				}

				return true;
			}
		}

		/// <summary>
		///     Compute the inverse of this matrix.
		/// </summary>
		/// <returns> the inverse of this matrix (newly created). </returns>
		public override Matrix computeInverse() {
			if(this.numRows != this.numColumns) {
				throw new ArithmeticException("Matrix is not invertible.");
			}

			// clone this matrix

			int[][] tmpMatrix = SquareArrays.ReturnRectangularIntArray(this.numRows, this.numRows);

			for(int i = this.numRows - 1; i >= 0; i--) {
				tmpMatrix[i] = IntUtils.clone(this.matrix[i]);
			}

			// initialize inverse matrix as unit matrix

			int[][] invMatrix = SquareArrays.ReturnRectangularIntArray(this.numRows, this.numRows);

			for(int i = this.numRows - 1; i >= 0; i--) {
				invMatrix[i][i] = 1;
			}

			// simultaneously compute Gaussian reduction of tmpMatrix and unit
			// matrix
			for(int i = 0; i < this.numRows; i++) {
				// if diagonal element is zero
				if(tmpMatrix[i][i] == 0) {
					bool foundNonZero = false;

					// find a non-zero element in the same column
					for(int j = i + 1; j < this.numRows; j++) {
						if(tmpMatrix[j][i] != 0) {
							// found it, swap rows ...
							foundNonZero = true;
							swapColumns(tmpMatrix, i, j);
							swapColumns(invMatrix, i, j);

							// ... and quit searching
							j = this.numRows;
						}
					}

					// if no non-zero element was found
					if(!foundNonZero) {
						// the matrix is not invertible
						throw new ArithmeticException("Matrix is not invertible.");
					}
				}

				// normalize i-th row
				int coef    = tmpMatrix[i][i];
				int invCoef = this.field.inverse(coef);
				this.multRowWithElementThis(tmpMatrix[i], invCoef);
				this.multRowWithElementThis(invMatrix[i], invCoef);

				// normalize all other rows
				for(int j = 0; j < this.numRows; j++) {
					if(j != i) {
						coef = tmpMatrix[j][i];

						if(coef != 0) {
							int[] tmpRow    = this.multRowWithElement(tmpMatrix[i], coef);
							int[] tmpInvRow = this.multRowWithElement(invMatrix[i], coef);
							this.addToRow(tmpRow, tmpMatrix[j]);
							this.addToRow(tmpInvRow, invMatrix[j]);
						}
					}
				}
			}

			return new GF2mMatrix(this.field, invMatrix);
		}

		private static void swapColumns(int[][] matrix, int first, int second) {
			int[] tmp = matrix[first];
			matrix[first]  = matrix[second];
			matrix[second] = tmp;
		}

		private void multRowWithElementThis(int[] row, int element) {
			for(int i = row.Length - 1; i >= 0; i--) {
				row[i] = this.field.mult(row[i], element);
			}
		}

		private int[] multRowWithElement(int[] row, int element) {
			int[] result = new int[row.Length];

			for(int i = row.Length - 1; i >= 0; i--) {
				result[i] = this.field.mult(row[i], element);
			}

			return result;
		}

		/// <summary>
		///     Add one row to another.
		/// </summary>
		/// <param name="fromRow"> the addend </param>
		/// <param name="toRow">   the row to add to </param>
		private void addToRow(int[] fromRow, int[] toRow) {
			for(int i = toRow.Length - 1; i >= 0; i--) {
				toRow[i] = this.field.add(fromRow[i], toRow[i]);
			}
		}

		public override Matrix rightMultiply(Matrix a) {
			throw new Exception("Not implemented.");
		}

		public override Matrix rightMultiply(Permutation perm) {
			throw new Exception("Not implemented.");
		}

		public override Vector leftMultiply(Vector vector) {
			throw new Exception("Not implemented.");
		}

		public override Vector rightMultiply(Vector vector) {
			throw new Exception("Not implemented.");
		}

		/// <summary>
		///     Checks if given object is equal to this matrix. The method returns false
		///     whenever the given object is not a matrix over GF(2^m).
		/// </summary>
		/// <param name="other"> object </param>
		/// <returns> true or false </returns>
		public override bool Equals(object other) {

			if((other == null) || !(other is GF2mMatrix)) {
				return false;
			}

			GF2mMatrix otherMatrix = (GF2mMatrix) other;

			if(!this.field.Equals(otherMatrix.field) || (otherMatrix.numRows != this.numColumns) || (otherMatrix.numColumns != this.numColumns)) {
				return false;
			}

			for(int i = 0; i < this.numRows; i++) {
				for(int j = 0; j < this.numColumns; j++) {
					if(this.matrix[i][j] != otherMatrix.matrix[i][j]) {
						return false;
					}
				}
			}

			return true;
		}

		public override int GetHashCode() {
			int hash = (((this.field.GetHashCode() * 31) + this.numRows) * 31) + this.numColumns;

			for(int i = 0; i < this.numRows; i++) {
				for(int j = 0; j < this.numColumns; j++) {
					hash = (hash * 31) + this.matrix[i][j];
				}
			}

			return hash;
		}

		public override string ToString() {
			string str = this.numRows + " x " + this.numColumns + " Matrix over " + this.field + ": \n";

			for(int i = 0; i < this.numRows; i++) {
				for(int j = 0; j < this.numColumns; j++) {
					str = str + this.field.elementToStr(this.matrix[i][j]) + " : ";
				}

				str = str + "\n";
			}

			return str;
		}
	}

}
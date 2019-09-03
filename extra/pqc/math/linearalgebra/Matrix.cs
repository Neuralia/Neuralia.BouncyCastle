using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	/// <summary>
	///     This abstract class defines matrices. It holds the number of rows and the
	///     number of columns of the matrix and defines some basic methods.
	/// </summary>
	public abstract class Matrix {

		// ----------------------------------------------------
		// some constants (matrix types)
		// ----------------------------------------------------

		/// <summary>
		///     zero matrix
		/// </summary>
		public const char MATRIX_TYPE_ZERO = 'Z';

		/// <summary>
		///     unit matrix
		/// </summary>
		public const char MATRIX_TYPE_UNIT = 'I';

		/// <summary>
		///     random lower triangular matrix
		/// </summary>
		public const char MATRIX_TYPE_RANDOM_LT = 'L';

		/// <summary>
		///     random upper triangular matrix
		/// </summary>
		public const char MATRIX_TYPE_RANDOM_UT = 'U';

		/// <summary>
		///     random regular matrix
		/// </summary>
		public const char MATRIX_TYPE_RANDOM_REGULAR = 'R';

		/// <summary>
		///     number of columns
		/// </summary>
		protected internal int numColumns;

		/// <summary>
		///     number of rows
		/// </summary>
		protected internal int numRows;

		// ----------------------------------------------------
		// getters
		// ----------------------------------------------------

		/// <returns> the number of rows in the matrix </returns>
		public virtual int NumRows => this.numRows;

		/// <returns> the number of columns in the binary matrix </returns>
		public virtual int NumColumns => this.numColumns;

		/// <returns> the encoded matrix, i.e., this matrix in byte array form. </returns>
		public abstract IByteArray Encoded { get; }

		/// <summary>
		///     Check if this is the zero matrix (i.e., all entries are zero).
		/// </summary>
		/// <returns> <tt>true</tt> if this is the zero matrix </returns>
		public abstract bool Zero { get; }

		// ----------------------------------------------------
		// arithmetic
		// ----------------------------------------------------

		/// <summary>
		///     Compute the inverse of this matrix.
		/// </summary>
		/// <returns> the inverse of this matrix (newly created). </returns>
		public abstract Matrix computeInverse();

		/// <summary>
		///     Compute the product of this matrix and another matrix.
		/// </summary>
		/// <param name="a"> the other matrix </param>
		/// <returns> <tt>this * a</tt> (newly created) </returns>
		public abstract Matrix rightMultiply(Matrix a);

		/// <summary>
		///     Compute the product of this matrix and a permutation.
		/// </summary>
		/// <param name="p"> the permutation </param>
		/// <returns> <tt>this * p</tt> (newly created) </returns>
		public abstract Matrix rightMultiply(Permutation p);

		/// <summary>
		///     Compute the product of a vector and this matrix. If the length of the
		///     vector is greater than the number of rows of this matrix, the matrix is
		///     multiplied by each m-bit part of the vector.
		/// </summary>
		/// <param name="vector"> a vector </param>
		/// <returns> <tt>vector * this</tt> (newly created) </returns>
		public abstract Vector leftMultiply(Vector vector);

		/// <summary>
		///     Compute the product of this matrix and a vector.
		/// </summary>
		/// <param name="vector"> a vector </param>
		/// <returns> <tt>this * vector</tt> (newly created) </returns>
		public abstract Vector rightMultiply(Vector vector);

		/// <returns> a human readable form of the matrix. </returns>
		public override abstract string ToString();
	}

}
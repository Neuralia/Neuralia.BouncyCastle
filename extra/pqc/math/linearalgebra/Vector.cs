using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	/// <summary>
	///     This abstract class defines vectors. It holds the length of vector.
	/// </summary>
	public abstract class Vector {

		/// <summary>
		///     the length of this vector
		/// </summary>
		protected internal int length;

		/// <returns> the length of this vector </returns>
		public int Length => this.length;

		/// <returns> this vector as byte array </returns>
		public abstract IByteArray Encoded { get; }

		/// <summary>
		///     Return whether this is the zero vector (i.e., all elements are zero).
		/// </summary>
		/// <returns>
		///     <tt>true</tt> if this is the zero vector, <tt>false</tt>
		///     otherwise
		/// </returns>
		public abstract bool Zero { get; }

		/// <summary>
		///     Add another vector to this vector.
		/// </summary>
		/// <param name="addend"> the other vector </param>
		/// <returns>
		///     <tt>this + addend</tt>
		/// </returns>
		public abstract Vector add(Vector addend);

		/// <summary>
		///     Multiply this vector with a permutation.
		/// </summary>
		/// <param name="p"> the permutation </param>
		/// <returns>
		///     <tt>this*p = p*this</tt>
		/// </returns>
		public abstract Vector multiply(Permutation p);

		/// <summary>
		///     Check if the given object is equal to this vector.
		/// </summary>
		/// <param name="other"> vector </param>
		/// <returns> the result of the comparison </returns>
		public override abstract bool Equals(object other);

		/// <returns> the hash code of this vector </returns>
		public override abstract int GetHashCode();

		/// <returns> a human readable form of this vector </returns>
		public override abstract string ToString();
	}

}
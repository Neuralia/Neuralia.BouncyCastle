using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This abstract class implements an element of the finite field
	///     <i>
	///         GF(2)
	///         <sup>
	///             n
	///         </sup>
	///     </i>
	///     in either <i>optimal normal basis</i> representation (<i>ONB</i>)
	///     or in <i>polynomial</i> representation. It is extended by the classes
	///     <a
	///         href= GF2nONBElement.html>
	///         <tt> GF2nONBElement</tt>
	///     </a>
	///     and
	///     <a href=
	///         GF2nPolynomialElement.html>
	///         <tt>GF2nPolynomialElement</tt>
	///     </a>
	///     .
	/// </summary>
	/// <seealso cref= GF2nPolynomialElement
	/// </seealso>
	/// <seealso cref= GF2nONBElement
	/// </seealso>
	/// <seealso cref= GF2nONBField
	/// </seealso>
	public abstract class GF2nElement : GFElement {

		/// <summary>
		///     holds the extension degree <i>n</i> of this element's corresponding
		///     field.
		/// </summary>
		protected internal int mDegree;

		// /////////////////////////////////////////////////////////////////////
		// member variables
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     holds a pointer to this element's corresponding field.
		/// </summary>
		protected internal GF2nField mField;

		/// <summary>
		///     Returns the field of this element.
		/// </summary>
		/// <returns> the field of this element </returns>
		public GF2nField Field => this.mField;

		public abstract          string      ToString(int radix);
		public override abstract string      ToString();
		public abstract          SafeArrayHandle toByteArray();
		public abstract          BigInteger  toFlexiBigInt();
		public abstract          GFElement   invert();
		public abstract          void        multiplyThisBy(GFElement factor);
		public abstract          GFElement   multiply(GFElement factor);
		public abstract          void        addToThis(GFElement addend);
		public abstract          GFElement   add(GFElement addend);
		public abstract          bool        One  { get; }
		public abstract          bool        Zero { get; }
		public override abstract int         GetHashCode();
		public override abstract bool        Equals(object other);

		// /////////////////////////////////////////////////////////////////////
		// pseudo-constructors
		// /////////////////////////////////////////////////////////////////////

		/// <returns> a copy of this GF2nElement </returns>
		public abstract object clone();

		/// <summary>
		///     Compute the difference of this element and <tt>minuend</tt>.
		/// </summary>
		/// <param name="minuend"> the minuend </param>
		/// <returns> <tt>this - minuend</tt> (newly created) </returns>
		public GFElement subtract(GFElement minuend) {
			return this.add(minuend);
		}

		/// <summary>
		///     Compute the difference of this element and <tt>minuend</tt>,
		///     overwriting this element.
		/// </summary>
		/// <param name="minuend"> the minuend </param>
		public void subtractFromThis(GFElement minuend) {
			this.addToThis(minuend);
		}

		// /////////////////////////////////////////////////////////////////////
		// assignments
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Assign the value 0 to this element.
		/// </summary>
		internal abstract void assignZero();

		/// <summary>
		///     Assigns the value 1 to this element.
		/// </summary>
		internal abstract void assignOne();

		// /////////////////////////////////////////////////////////////////////
		// access
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns whether the rightmost bit of the bit representation is set. This
		///     is needed for data conversion according to 1363.
		/// </summary>
		/// <returns> true if the rightmost bit of this element is set </returns>
		public abstract bool testRightmostBit();

		/// <summary>
		///     Checks whether the indexed bit of the bit representation is set
		/// </summary>
		/// <param name="index"> the index of the bit to test </param>
		/// <returns> <tt>true</tt> if the indexed bit is set </returns>
		internal abstract bool testBit(int index);

		// /////////////////////////////////////////////////////////////////////
		// arithmetic
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns <tt>this</tt> element + 1.
		/// </summary>
		/// <returns> <tt>this</tt> + 1 </returns>
		public abstract GF2nElement increase();

		/// <summary>
		///     Increases this element by one.
		/// </summary>
		public abstract void increaseThis();

		/// <summary>
		///     Returns <tt>this</tt> element to the power of 2.
		/// </summary>
		/// <returns>
		///     <tt>this</tt><sup>2</sup>
		/// </returns>
		public abstract GF2nElement square();

		/// <summary>
		///     Squares <tt>this</tt> element.
		/// </summary>
		public abstract void squareThis();

		/// <summary>
		///     Compute the square root of this element and return the result in a new
		///     <seealso cref="GF2nElement" />.
		/// </summary>
		/// <returns> <tt>this<sup>1/2</sup></tt> (newly created) </returns>
		public abstract GF2nElement squareRoot();

		/// <summary>
		///     Compute the square root of this element.
		/// </summary>
		public abstract void squareRootThis();

		/// <summary>
		///     Performs a basis transformation of this element to the given GF2nField
		///     <tt>basis</tt>.
		/// </summary>
		/// <param name="basis"> the GF2nField representation to transform this element to </param>
		/// <returns> this element in the representation of <tt>basis</tt> </returns>
		public GF2nElement convert(GF2nField basis) {
			return this.mField.convert(this, basis);
		}

		/// <summary>
		///     Returns the trace of this element.
		/// </summary>
		/// <returns> the trace of this element </returns>
		public abstract int trace();

		/// <summary>
		///     Solves a quadratic equation.
		///     <br>
		///         Let z<sup>2</sup> + z = <tt>this</tt>. Then this method returns z.
		/// </summary>
		/// <returns> z with z<sup>2</sup> + z = <tt>this</tt> </returns>
		public abstract GF2nElement solveQuadraticEquation();
	}

}
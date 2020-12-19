using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This interface defines a finite field element. It is implemented by the
	///     class <seealso cref="GF2nElement" />.
	/// </summary>
	/// <seealso cref= GF2nElement
	/// </seealso>
	public interface GFElement {

		/// <summary>
		///     Checks whether this element is zero.
		/// </summary>
		/// <returns> <tt>true</tt> if <tt>this</tt> is the zero element </returns>
		bool Zero { get; }

		/// <summary>
		///     Checks whether this element is one.
		/// </summary>
		/// <returns> <tt>true</tt> if <tt>this</tt> is the one element </returns>
		bool One { get; }

		/// <returns> a copy of this GFElement </returns>
		object clone();

		// /////////////////////////////////////////////////////////////////
		// comparison
		// /////////////////////////////////////////////////////////////////

		/// <summary>
		///     Compare this curve with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		bool Equals(object other);

		/// <returns> the hash code of this element </returns>
		int GetHashCode();

		// /////////////////////////////////////////////////////////////////////
		// arithmetic
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Compute the sum of this element and the addend.
		/// </summary>
		/// <param name="addend"> the addend </param>
		/// <returns> <tt>this + other</tt> (newly created) </returns>
		GFElement add(GFElement addend);

		/// <summary>
		///     Compute the sum of this element and the addend, overwriting this element.
		/// </summary>
		/// <param name="addend"> the addend </param>
		void addToThis(GFElement addend);

		/// <summary>
		///     Compute the difference of this element and <tt>minuend</tt>.
		/// </summary>
		/// <param name="minuend"> the minuend </param>
		/// <returns> <tt>this - minuend</tt> (newly created) </returns>
		GFElement subtract(GFElement minuend);

		/// <summary>
		///     Compute the difference of this element and <tt>minuend</tt>,
		///     overwriting this element.
		/// </summary>
		/// <param name="minuend"> the minuend </param>
		void subtractFromThis(GFElement minuend);

		/// <summary>
		///     Compute the product of this element and <tt>factor</tt>.
		/// </summary>
		/// <param name="factor"> the factor </param>
		/// <returns> <tt>this * factor</tt> (newly created) </returns>
		GFElement multiply(GFElement factor);

		/// <summary>
		///     Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="factor"> the factor </param>
		void multiplyThisBy(GFElement factor);

		/// <summary>
		///     Compute the multiplicative inverse of this element.
		/// </summary>
		/// <returns> <tt>this<sup>-1</sup></tt> (newly created) </returns>
		/// <exception cref="ArithmeticException"> if <tt>this</tt> is the zero element. </exception>
		GFElement invert();

		// /////////////////////////////////////////////////////////////////////
		// conversion
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns this element as FlexiBigInt. The conversion is
		///     <a
		///         href="http://grouper.ieee.org/groups/1363/">
		///         P1363
		///     </a>
		///     -conform.
		/// </summary>
		/// <returns> this element as BigInt </returns>
		BigInteger toFlexiBigInt();

		/// <summary>
		///     Returns this element as byte array. The conversion is <a href="http://grouper.ieee.org/groups/1363/">P1363</a>
		///     -conform.
		/// </summary>
		/// <returns> this element as byte array </returns>
		SafeArrayHandle toByteArray();

		/// <summary>
		///     Return a String representation of this element.
		/// </summary>
		/// <returns> String representation of this element </returns>
		string ToString();

		/// <summary>
		///     Return a String representation of this element. <tt>radix</tt>
		///     specifies the radix of the String representation.
		/// </summary>
		/// <param name="radix"> specifies the radix of the String representation </param>
		/// <returns> String representation of this element with the specified radix </returns>
		string ToString(int radix);
	}

}
using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements elements of finite binary fields <i>GF(2<sup>n</sup>)</i>
	///     using polynomial representation. For more information on the arithmetic see
	///     for example IEEE Standard 1363 or
	///     <a
	///         href= http:// www.certicom.com/ research/ online.html>
	///         Certicom online-tutorial
	///     </a>
	///     .
	/// </summary>
	/// <seealso cref="GF2nField"
	/// </seealso>
	/// <seealso cref= GF2nPolynomialField
	/// </seealso>
	/// <seealso cref= GF2nONBElement
	/// </seealso>
	/// <seealso cref= GF2Polynomial
	/// </seealso>
	public class GF2nPolynomialElement : GF2nElement {

		// pre-computed Bitmask for fast masking, bitMask[a]=0x1 << a
		private static readonly int[] bitMask = {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, unchecked((int) 0x80000000), 0x00000000};

		// the used GF2Polynomial which stores the coefficients
		private GF2Polynomial polynomial;

		/// <summary>
		///     Create a new random GF2nPolynomialElement using the given field and
		///     source of randomness.
		/// </summary>
		/// <param name="f">    the GF2nField to use </param>
		/// <param name="rand"> the source of randomness </param>
		public GF2nPolynomialElement(GF2nPolynomialField f, Random rand) {
			this.mField     = f;
			this.mDegree    = this.mField.Degree;
			this.polynomial = new GF2Polynomial(this.mDegree);
			this.randomize(rand);
		}

		/// <summary>
		///     Creates a new GF2nPolynomialElement using the given field and Bitstring.
		/// </summary>
		/// <param name="f">  the GF2nPolynomialField to use </param>
		/// <param name="bs"> the desired value as Bitstring </param>
		public GF2nPolynomialElement(GF2nPolynomialField f, GF2Polynomial bs) {
			this.mField     = f;
			this.mDegree    = this.mField.Degree;
			this.polynomial = new GF2Polynomial(bs);
			this.polynomial.expandN(this.mDegree);
		}

		/// <summary>
		///     Creates a new GF2nPolynomialElement using the given field <i>f</i> and
		///     IByteArray <i>os</i> as value. The conversion is done according to 1363.
		/// </summary>
		/// <param name="f">  the GF2nField to use </param>
		/// <param name="os"> the octet string to assign to this GF2nPolynomialElement </param>
		/// <seealso cref="P1363 5.5.5 p23, OS2FEP/OS2BSP"
		/// </seealso>
		public GF2nPolynomialElement(GF2nPolynomialField f, IByteArray os) {
			this.mField     = f;
			this.mDegree    = this.mField.Degree;
			this.polynomial = new GF2Polynomial(this.mDegree, os);
			this.polynomial.expandN(this.mDegree);
		}

		/// <summary>
		///     Creates a new GF2nPolynomialElement using the given field <i>f</i> and
		///     int[] <i>is</i> as value.
		/// </summary>
		/// <param name="f">  the GF2nField to use </param>
		/// <param name="is"> the integer string to assign to this GF2nPolynomialElement </param>
		public GF2nPolynomialElement(GF2nPolynomialField f, int[] @is) {
			this.mField     = f;
			this.mDegree    = this.mField.Degree;
			this.polynomial = new GF2Polynomial(this.mDegree, @is);
			this.polynomial.expandN(f.mDegree);
		}

		/// <summary>
		///     Creates a new GF2nPolynomialElement by cloning the given
		///     GF2nPolynomialElement <i>b</i>.
		/// </summary>
		/// <param name="other"> the GF2nPolynomialElement to clone </param>
		public GF2nPolynomialElement(GF2nPolynomialElement other) {
			this.mField     = other.mField;
			this.mDegree    = other.mDegree;
			this.polynomial = new GF2Polynomial(other.polynomial);
		}

		// /////////////////////////////////////////////////////////////////////
		// comparison
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Checks whether this element is zero.
		/// </summary>
		/// <returns> <tt>true</tt> if <tt>this</tt> is the zero element </returns>
		public override bool Zero => this.polynomial.Zero;

		/// <summary>
		///     Tests if the GF2nPolynomialElement has 'one' as value.
		/// </summary>
		/// <returns> true if <i>this</i> equals one (this == 1) </returns>
		public override bool One => this.polynomial.One;

		// /////////////////////////////////////////////////////////////////////
		// access
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns the value of this GF2nPolynomialElement in a new Bitstring.
		/// </summary>
		/// <returns> the value of this GF2nPolynomialElement in a new Bitstring </returns>
		private GF2Polynomial GF2Polynomial => new GF2Polynomial(this.polynomial);

		// /////////////////////////////////////////////////////////////////////
		// pseudo-constructors
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Creates a new GF2nPolynomialElement by cloning this
		///     GF2nPolynomialElement.
		/// </summary>
		/// <returns> a copy of this element </returns>
		public override object clone() {
			return new GF2nPolynomialElement(this);
		}

		// /////////////////////////////////////////////////////////////////////
		// assignments
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Assigns the value 'zero' to this Polynomial.
		/// </summary>
		internal override void assignZero() {
			this.polynomial.assignZero();
		}

		/// <summary>
		///     Create the zero element.
		/// </summary>
		/// <param name="f"> the finite field </param>
		/// <returns> the zero element in the given finite field </returns>
		public static GF2nPolynomialElement ZERO(GF2nPolynomialField f) {
			GF2Polynomial polynomial = new GF2Polynomial(f.Degree);

			return new GF2nPolynomialElement(f, polynomial);
		}

		/// <summary>
		///     Create the one element.
		/// </summary>
		/// <param name="f"> the finite field </param>
		/// <returns> the one element in the given finite field </returns>
		public static GF2nPolynomialElement ONE(GF2nPolynomialField f) {
			GF2Polynomial polynomial = new GF2Polynomial(f.Degree, new[] {1});

			return new GF2nPolynomialElement(f, polynomial);
		}

		/// <summary>
		///     Assigns the value 'one' to this Polynomial.
		/// </summary>
		internal override void assignOne() {
			this.polynomial.assignOne();
		}

		/// <summary>
		///     Assign a random value to this GF2nPolynomialElement using the specified
		///     source of randomness.
		/// </summary>
		/// <param name="rand"> the source of randomness </param>
		private void randomize(Random rand) {
			this.polynomial.expandN(this.mDegree);
			this.polynomial.randomize(rand);
		}

		/// <summary>
		///     Compare this element with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns>
		///     <tt>true</tt> if the two objects are equal, <tt>false</tt>
		///     otherwise
		/// </returns>
		public override bool Equals(object other) {
			if((other == null) || !(other is GF2nPolynomialElement)) {
				return false;
			}

			GF2nPolynomialElement otherElem = (GF2nPolynomialElement) other;

			if(this.mField != otherElem.mField) {
				if(!this.mField.FieldPolynomial.Equals(otherElem.mField.FieldPolynomial)) {
					return false;
				}
			}

			return this.polynomial.Equals(otherElem.polynomial);
		}

		/// <returns> the hash code of this element </returns>
		public override int GetHashCode() {
			return this.mField.GetHashCode() + this.polynomial.GetHashCode();
		}

		/// <summary>
		///     Checks whether the indexed bit of the bit representation is set.
		/// </summary>
		/// <param name="index"> the index of the bit to test </param>
		/// <returns> <tt>true</tt> if the indexed bit is set </returns>
		internal override bool testBit(int index) {
			return this.polynomial.testBit(index);
		}

		/// <summary>
		///     Returns whether the rightmost bit of the bit representation is set. This
		///     is needed for data conversion according to 1363.
		/// </summary>
		/// <returns> true if the rightmost bit of this element is set </returns>
		public override bool testRightmostBit() {
			return this.polynomial.testBit(0);
		}

		/// <summary>
		///     Compute the sum of this element and <tt>addend</tt>.
		/// </summary>
		/// <param name="addend"> the addend </param>
		/// <returns> <tt>this + other</tt> (newly created) </returns>
		public override GFElement add(GFElement addend) {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.addToThis(addend);

			return result;
		}

		/// <summary>
		///     Compute <tt>this + addend</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="addend"> the addend </param>
		public override void addToThis(GFElement addend) {
			if(!(addend is GF2nPolynomialElement)) {
				throw new Exception();
			}

			if(!this.mField.Equals(((GF2nPolynomialElement) addend).mField)) {
				throw new Exception();
			}

			this.polynomial.addToThis(((GF2nPolynomialElement) addend).polynomial);
		}

		/// <summary>
		///     Returns <tt>this</tt> element + 'one".
		/// </summary>
		/// <returns> <tt>this</tt> + 'one' </returns>
		public override GF2nElement increase() {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.increaseThis();

			return result;
		}

		/// <summary>
		///     Increases this element by 'one'.
		/// </summary>
		public override void increaseThis() {
			this.polynomial.increaseThis();
		}

		/// <summary>
		///     Compute the product of this element and <tt>factor</tt>.
		/// </summary>
		/// <param name="factor"> the factor </param>
		/// <returns> <tt>this * factor</tt> (newly created) </returns>
		public override GFElement multiply(GFElement factor) {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.multiplyThisBy(factor);

			return result;
		}

		/// <summary>
		///     Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="factor"> the factor </param>
		public override void multiplyThisBy(GFElement factor) {
			if(!(factor is GF2nPolynomialElement)) {
				throw new Exception();
			}

			if(!this.mField.Equals(((GF2nPolynomialElement) factor).mField)) {
				throw new Exception();
			}

			if(this.Equals(factor)) {
				this.squareThis();

				return;
			}

			this.polynomial = this.polynomial.multiply(((GF2nPolynomialElement) factor).polynomial);
			this.reduceThis();
		}

		/// <summary>
		///     Compute the multiplicative inverse of this element.
		/// </summary>
		/// <returns> <tt>this<sup>-1</sup></tt> (newly created) </returns>
		/// <exception cref="ArithmeticException"> if <tt>this</tt> is the zero element. </exception>
		/// <seealso cref= GF2nPolynomialElement# invertMAIA
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# invertEEA
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# invertSquare
		/// </seealso>
		public override GFElement invert() {
			return this.invertMAIA();
		}

		/// <summary>
		///     Calculates the multiplicative inverse of <i>this</i> and returns the
		///     result in a new GF2nPolynomialElement.
		/// </summary>
		/// <returns> <i>this</i>^(-1) </returns>
		/// <exception cref="ArithmeticException"> if <i>this</i> equals zero </exception>
		public virtual GF2nPolynomialElement invertEEA() {
			if(this.Zero) {
				throw new ArithmeticException();
			}

			GF2Polynomial b = new GF2Polynomial(this.mDegree + 32, "ONE");
			b.reduceN();
			GF2Polynomial c = new GF2Polynomial(this.mDegree + 32);
			c.reduceN();
			GF2Polynomial u = this.GF2Polynomial;
			GF2Polynomial v = this.mField.FieldPolynomial;
			GF2Polynomial h;
			int           j;
			u.reduceN();

			while(!u.One) {
				u.reduceN();
				v.reduceN();
				j = u.Length - v.Length;

				if(j < 0) {
					h = u;
					u = v;
					v = h;
					h = b;
					b = c;
					c = h;
					j = -j;
					c.reduceN(); // this increases the performance
				}

				u.shiftLeftAddThis(v, j);
				b.shiftLeftAddThis(c, j);
			}

			b.reduceN();

			return new GF2nPolynomialElement((GF2nPolynomialField) this.mField, b);
		}

		/// <summary>
		///     Calculates the multiplicative inverse of <i>this</i> and returns the
		///     result in a new GF2nPolynomialElement.
		/// </summary>
		/// <returns> <i>this</i>^(-1) </returns>
		/// <exception cref="ArithmeticException"> if <i>this</i> equals zero </exception>
		public virtual GF2nPolynomialElement invertSquare() {
			GF2nPolynomialElement n;
			GF2nPolynomialElement u;
			int                   i, j, k, b;

			if(this.Zero) {
				throw new ArithmeticException();
			}

			// b = (n-1)
			b = this.mField.Degree - 1;

			// n = a
			n = new GF2nPolynomialElement(this);
			n.polynomial.expandN((this.mDegree << 1) + 32); // increase performance
			n.polynomial.reduceN();

			// k = 1
			k = 1;

			// for i = (r-1) downto 0 do, r=bitlength(b)
			for(i = IntegerFunctions.floorLog(b) - 1; i >= 0; i--) {
				// u = n
				u = new GF2nPolynomialElement(n);

				// for j = 1 to k do
				for(j = 1; j <= k; j++) {
					// u = u^2
					u.squareThisPreCalc();
				}

				// n = nu
				n.multiplyThisBy(u);

				// k = 2k
				k <<= 1;

				// if b(i)==1
				if((b & bitMask[i]) != 0) {
					// n = n^2 * b
					n.squareThisPreCalc();
					n.multiplyThisBy(this);

					// k = k+1
					k += 1;
				}
			}

			// outpur n^2
			n.squareThisPreCalc();

			return n;
		}

		/// <summary>
		///     Calculates the multiplicative inverse of <i>this</i> using the modified
		///     almost inverse algorithm and returns the result in a new
		///     GF2nPolynomialElement.
		/// </summary>
		/// <returns> <i>this</i>^(-1) </returns>
		/// <exception cref="ArithmeticException"> if <i>this</i> equals zero </exception>
		public virtual GF2nPolynomialElement invertMAIA() {
			if(this.Zero) {
				throw new ArithmeticException();
			}

			GF2Polynomial b = new GF2Polynomial(this.mDegree, "ONE");
			GF2Polynomial c = new GF2Polynomial(this.mDegree);
			GF2Polynomial u = this.GF2Polynomial;
			GF2Polynomial v = this.mField.FieldPolynomial;
			GF2Polynomial h;

			while(true) {
				while(!u.testBit(0)) {
					// x|u (x divides u)
					u.shiftRightThis(); // u = u / x

					if(!b.testBit(0)) {
						b.shiftRightThis();
					} else {
						b.addToThis(this.mField.FieldPolynomial);
						b.shiftRightThis();
					}
				}

				if(u.One) {
					return new GF2nPolynomialElement((GF2nPolynomialField) this.mField, b);
				}

				u.reduceN();
				v.reduceN();

				if(u.Length < v.Length) {
					h = u;
					u = v;
					v = h;
					h = b;
					b = c;
					c = h;
				}

				u.addToThis(v);
				b.addToThis(c);
			}
		}

		/// <summary>
		///     This method is used internally to map the square()-calls within
		///     GF2nPolynomialElement to one of the possible squaring methods.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2nPolynomialElement# squarePreCalc
		/// </seealso>
		public override GF2nElement square() {
			return this.squarePreCalc();
		}

		/// <summary>
		///     This method is used internally to map the square()-calls within
		///     GF2nPolynomialElement to one of the possible squaring methods.
		/// </summary>
		public override void squareThis() {
			this.squareThisPreCalc();
		}

		/// <summary>
		///     Squares this GF2nPolynomialElement using GF2nField's squaring matrix.
		///     This is supposed to be fast when using a polynomial (no tri- or
		///     pentanomial) as fieldpolynomial. Use squarePreCalc when using a tri- or
		///     pentanomial as fieldpolynomial instead.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2Polynomial# vectorMult
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# squarePreCalc
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# squareBitwise
		/// </seealso>
		public virtual GF2nPolynomialElement squareMatrix() {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareThisMatrix();
			result.reduceThis();

			return result;
		}

		/// <summary>
		///     Squares this GF2nPolynomialElement using GF2nFields squaring matrix. This
		///     is supposed to be fast when using a polynomial (no tri- or pentanomial)
		///     as fieldpolynomial. Use squarePreCalc when using a tri- or pentanomial as
		///     fieldpolynomial instead.
		/// </summary>
		/// <seealso cref= GF2Polynomial# vectorMult
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# squarePreCalc
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# squareBitwise
		/// </seealso>
		public virtual void squareThisMatrix() {
			GF2Polynomial result = new GF2Polynomial(this.mDegree);

			for(int i = 0; i < this.mDegree; i++) {
				if(this.polynomial.vectorMult(((GF2nPolynomialField) this.mField).squaringMatrix[this.mDegree - i - 1])) {
					result.Bit = i;

				}
			}

			this.polynomial = result;
		}

		/// <summary>
		///     Squares this GF2nPolynomialElement by shifting left its Bitstring and
		///     reducing. This is supposed to be the slowest method. Use squarePreCalc or
		///     squareMatrix instead.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2nPolynomialElement# squareMatrix
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# squarePreCalc
		/// </seealso>
		/// <seealso cref= GF2Polynomial# squareThisBitwise
		/// </seealso>
		public virtual GF2nPolynomialElement squareBitwise() {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareThisBitwise();
			result.reduceThis();

			return result;
		}

		/// <summary>
		///     Squares this GF2nPolynomialElement by shifting left its Bitstring and
		///     reducing. This is supposed to be the slowest method. Use squarePreCalc or
		///     squareMatrix instead.
		/// </summary>
		/// <seealso cref= GF2nPolynomialElement# squareMatrix
		/// </seealso>
		/// <seealso cref= GF2nPolynomialElement# squarePreCalc
		/// </seealso>
		/// <seealso cref= GF2Polynomial# squareThisBitwise
		/// </seealso>
		public virtual void squareThisBitwise() {
			this.polynomial.squareThisBitwise();
			this.reduceThis();
		}

		/// <summary>
		///     Squares this GF2nPolynomialElement by using precalculated values and
		///     reducing. This is supposed to de fastest when using a trinomial or
		///     pentanomial as field polynomial. Use squareMatrix when using a ordinary
		///     polynomial as field polynomial.
		/// </summary>
		/// <returns> <tt>this<sup>2</sup></tt> (newly created) </returns>
		/// <seealso cref= GF2nPolynomialElement# squareMatrix
		/// </seealso>
		/// <seealso cref= GF2Polynomial# squareThisPreCalc
		/// </seealso>
		public virtual GF2nPolynomialElement squarePreCalc() {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareThisPreCalc();
			result.reduceThis();

			return result;
		}

		/// <summary>
		///     Squares this GF2nPolynomialElement by using precalculated values and
		///     reducing. This is supposed to de fastest when using a tri- or pentanomial
		///     as fieldpolynomial. Use squareMatrix when using a ordinary polynomial as
		///     fieldpolynomial.
		/// </summary>
		/// <seealso cref= GF2nPolynomialElement# squareMatrix
		/// </seealso>
		/// <seealso cref= GF2Polynomial# squareThisPreCalc
		/// </seealso>
		public virtual void squareThisPreCalc() {
			this.polynomial.squareThisPreCalc();
			this.reduceThis();
		}

		/// <summary>
		///     Calculates <i>this</i> to the power of <i>k</i> and returns the result
		///     in a new GF2nPolynomialElement.
		/// </summary>
		/// <param name="k"> the power </param>
		/// <returns> <i>this</i>^<i>k</i> in a new GF2nPolynomialElement </returns>
		public virtual GF2nPolynomialElement power(int k) {
			if(k == 1) {
				return new GF2nPolynomialElement(this);
			}

			GF2nPolynomialElement result = ONE((GF2nPolynomialField) this.mField);

			if(k == 0) {
				return result;
			}

			GF2nPolynomialElement x = new GF2nPolynomialElement(this);
			x.polynomial.expandN((x.mDegree << 1) + 32); // increase performance
			x.polynomial.reduceN();

			for(int i = 0; i < this.mDegree; i++) {
				if((k & (1 << i)) != 0) {
					result.multiplyThisBy(x);
				}

				x.square();
			}

			return result;
		}

		/// <summary>
		///     Compute the square root of this element and return the result in a new
		///     <seealso cref="GF2nPolynomialElement" />.
		/// </summary>
		/// <returns> <tt>this<sup>1/2</sup></tt> (newly created) </returns>
		public override GF2nElement squareRoot() {
			GF2nPolynomialElement result = new GF2nPolynomialElement(this);
			result.squareRootThis();

			return result;
		}

		/// <summary>
		///     Compute the square root of this element.
		/// </summary>
		public override void squareRootThis() {
			// increase performance
			this.polynomial.expandN((this.mDegree << 1) + 32);
			this.polynomial.reduceN();

			for(int i = 0; i < (this.mField.Degree - 1); i++) {
				this.squareThis();
			}
		}

		/// <summary>
		///     Solves the quadratic equation <tt>z<sup>2</sup> + z = this</tt> if
		///     such a solution exists. This method returns one of the two possible
		///     solutions. The other solution is <tt>z + 1</tt>. Use z.increase() to
		///     compute this solution.
		/// </summary>
		/// <returns>
		///     a GF2nPolynomialElement representing one z satisfying the
		///     equation <tt>z<sup>2</sup> + z = this</tt>
		/// </returns>
		/// <seealso cref="IEEE 1363, Annex A.4.7"
		/// </seealso>
		public override GF2nElement solveQuadraticEquation() {
			if(this.Zero) {
				return ZERO((GF2nPolynomialField) this.mField);
			}

			if((this.mDegree & 1) == 1) {
				return this.halfTrace();
			}

			// TODO this can be sped-up by precomputation of p and w's
			GF2nPolynomialElement z, w;

			do {
				// step 1.
				GF2nPolynomialElement p = new GF2nPolynomialElement((GF2nPolynomialField) this.mField, new Random());

				// step 2.
				z = ZERO((GF2nPolynomialField) this.mField);
				w = (GF2nPolynomialElement) p.clone();

				// step 3.
				for(int i = 1; i < this.mDegree; i++) {
					// compute z = z^2 + w^2 * this
					// and w = w^2 + p
					z.squareThis();
					w.squareThis();
					z.addToThis(w.multiply(this));
					w.addToThis(p);
				}
			} while(w.Zero); // step 4.

			if(!this.Equals(z.square().add(z))) {
				throw new Exception();
			}

			// step 5.
			return z;
		}

		/// <summary>
		///     Returns the trace of this GF2nPolynomialElement.
		/// </summary>
		/// <returns> the trace of this GF2nPolynomialElement </returns>
		public override int trace() {
			GF2nPolynomialElement t = new GF2nPolynomialElement(this);
			int                   i;

			for(i = 1; i < this.mDegree; i++) {
				t.squareThis();
				t.addToThis(this);
			}

			if(t.One) {
				return 1;
			}

			return 0;
		}

		/// <summary>
		///     Returns the half-trace of this GF2nPolynomialElement.
		/// </summary>
		/// <returns>
		///     a GF2nPolynomialElement representing the half-trace of this
		///     GF2nPolynomialElement.
		/// </returns>
		private GF2nPolynomialElement halfTrace() {
			if((this.mDegree & 0x01) == 0) {
				throw new Exception();
			}

			int                   i;
			GF2nPolynomialElement h = new GF2nPolynomialElement(this);

			for(i = 1; i <= ((this.mDegree - 1) >> 1); i++) {
				h.squareThis();
				h.squareThis();
				h.addToThis(this);
			}

			return h;
		}

		/// <summary>
		///     Reduces this GF2nPolynomialElement modulo the field-polynomial.
		/// </summary>
		/// <seealso cref= GF2Polynomial# reduceTrinomial
		/// </seealso>
		/// <seealso cref= GF2Polynomial# reducePentanomial
		/// </seealso>
		private void reduceThis() {
			if(this.polynomial.Length > this.mDegree) {
				// really reduce ?
				if(((GF2nPolynomialField) this.mField).Trinomial) {
					// fieldpolonomial
					// is trinomial
					int tc;

					try {
						tc = ((GF2nPolynomialField) this.mField).Tc;
					} catch(Exception) {
						throw new Exception("GF2nPolynomialElement.reduce: the field" + " polynomial is not a trinomial");
					}

					if(((this.mDegree - tc) <= 32) || (this.polynomial.Length > (this.mDegree << 1))) // do we have to use slow
					{
						// bitwise reduction ?
						this.reduceTrinomialBitwise(tc);

						return;
					}

					this.polynomial.reduceTrinomial(this.mDegree, tc);

					return;
				}

				if(((GF2nPolynomialField) this.mField).Pentanomial) {
					// fieldpolynomial
					// is
					// pentanomial
					int[] pc;

					try {
						pc = ((GF2nPolynomialField) this.mField).Pc;
					} catch(Exception) {
						throw new Exception("GF2nPolynomialElement.reduce: the field" + " polynomial is not a pentanomial");
					}

					if(((this.mDegree - pc[2]) <= 32) || (this.polynomial.Length > (this.mDegree << 1))) // do we have to use slow
					{
						// bitwise reduction ?
						this.reducePentanomialBitwise(pc);

						return;
					}

					this.polynomial.reducePentanomial(this.mDegree, pc);

					return;
				}

				// fieldpolynomial is something else
				this.polynomial = this.polynomial.remainder(this.mField.FieldPolynomial);
				this.polynomial.expandN(this.mDegree);

				return;
			}

			if(this.polynomial.Length < this.mDegree) {
				this.polynomial.expandN(this.mDegree);
			}
		}

		/// <summary>
		///     Reduce this GF2nPolynomialElement using the trinomial x^n + x^tc + 1 as
		///     fieldpolynomial. The coefficients are reduced bit by bit.
		/// </summary>
		private void reduceTrinomialBitwise(int tc) {
			int i;
			int k = this.mDegree - tc;

			for(i = this.polynomial.Length - 1; i >= this.mDegree; i--) {
				if(this.polynomial.testBit(i)) {

					this.polynomial.xorBit(i);
					this.polynomial.xorBit(i - k);
					this.polynomial.xorBit(i - this.mDegree);

				}
			}

			this.polynomial.reduceN();
			this.polynomial.expandN(this.mDegree);
		}

		/// <summary>
		///     Reduce this GF2nPolynomialElement using the pentanomial x^n + x^pc[2] +
		///     x^pc[1] + x^pc[0] + 1 as fieldpolynomial. The coefficients are reduced
		///     bit by bit.
		/// </summary>
		private void reducePentanomialBitwise(int[] pc) {
			int i;
			int k = this.mDegree - pc[2];
			int l = this.mDegree - pc[1];
			int m = this.mDegree - pc[0];

			for(i = this.polynomial.Length - 1; i >= this.mDegree; i--) {
				if(this.polynomial.testBit(i)) {
					this.polynomial.xorBit(i);
					this.polynomial.xorBit(i - k);
					this.polynomial.xorBit(i - l);
					this.polynomial.xorBit(i - m);
					this.polynomial.xorBit(i - this.mDegree);

				}
			}

			this.polynomial.reduceN();
			this.polynomial.expandN(this.mDegree);
		}

		// /////////////////////////////////////////////////////////////////////
		// conversion
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns a string representing this Bitstrings value using hexadecimal
		///     radix in MSB-first order.
		/// </summary>
		/// <returns> a String representing this Bitstrings value. </returns>
		public override string ToString() {
			return this.polynomial.ToString(16);
		}

		/// <summary>
		///     Returns a string representing this Bitstrings value using hexadecimal or
		///     binary radix in MSB-first order.
		/// </summary>
		/// <param name="radix"> the radix to use (2 or 16, otherwise 2 is used) </param>
		/// <returns> a String representing this Bitstrings value. </returns>
		public override string ToString(int radix) {
			return this.polynomial.ToString(radix);
		}

		/// <summary>
		///     Converts this GF2nPolynomialElement to a IByteArray according to 1363.
		/// </summary>
		/// <returns> a IByteArray representing the value of this GF2nPolynomialElement </returns>
		/// <seealso cref="P1363 5.5.2 p22f BS2OSP, FE2OSP"
		/// </seealso>
		public override IByteArray toByteArray() {
			return this.polynomial.toByteArray();
		}

		/// <summary>
		///     Converts this GF2nPolynomialElement to an integer according to 1363.
		/// </summary>
		/// <returns>
		///     a BigInteger representing the value of this
		///     GF2nPolynomialElement
		/// </returns>
		/// <seealso cref="P1363 5.5.1 p22 BS2IP"
		/// </seealso>
		public override BigInteger toFlexiBigInt() {
			return this.polynomial.toFlexiBigInt();
		}
	}

}
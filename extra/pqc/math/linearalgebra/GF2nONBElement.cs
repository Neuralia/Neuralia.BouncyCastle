using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements an element of the finite field <i>GF(2<sup>n </sup>)</i>.
	///     It is represented in an optimal normal basis representation and holds the
	///     pointer <tt>mField</tt> to its corresponding field.
	/// </summary>
	/// <seealso cref= GF2nField
	/// </seealso>
	/// <seealso cref= GF2nElement
	/// </seealso>
	public class GF2nONBElement : GF2nElement {

		private const int MAXLONG = 64;

		// /////////////////////////////////////////////////////////////////////
		// member variables
		// /////////////////////////////////////////////////////////////////////

		private static readonly long[] mBitmask = {0x0000000000000001L, 0x0000000000000002L, 0x0000000000000004L, 0x0000000000000008L, 0x0000000000000010L, 0x0000000000000020L, 0x0000000000000040L, 0x0000000000000080L, 0x0000000000000100L, 0x0000000000000200L, 0x0000000000000400L, 0x0000000000000800L, 0x0000000000001000L, 0x0000000000002000L, 0x0000000000004000L, 0x0000000000008000L, 0x0000000000010000L, 0x0000000000020000L, 0x0000000000040000L, 0x0000000000080000L, 0x0000000000100000L, 0x0000000000200000L, 0x0000000000400000L, 0x0000000000800000L, 0x0000000001000000L, 0x0000000002000000L, 0x0000000004000000L, 0x0000000008000000L, 0x0000000010000000L, 0x0000000020000000L, 0x0000000040000000L, 0x0000000080000000L, 0x0000000100000000L, 0x0000000200000000L, 0x0000000400000000L, 0x0000000800000000L, 0x0000001000000000L, 0x0000002000000000L, 0x0000004000000000L, 0x0000008000000000L, 0x0000010000000000L, 0x0000020000000000L, 0x0000040000000000L, 0x0000080000000000L, 0x0000100000000000L, 0x0000200000000000L, 0x0000400000000000L, 0x0000800000000000L, 0x0001000000000000L, 0x0002000000000000L, 0x0004000000000000L, 0x0008000000000000L, 0x0010000000000000L, 0x0020000000000000L, 0x0040000000000000L, 0x0080000000000000L, 0x0100000000000000L, 0x0200000000000000L, 0x0400000000000000L, 0x0800000000000000L, 0x1000000000000000L, 0x2000000000000000L, 0x4000000000000000L, unchecked((long) 0x8000000000000000L)};

		private static readonly long[] mMaxmask = {0x0000000000000001L, 0x0000000000000003L, 0x0000000000000007L, 0x000000000000000FL, 0x000000000000001FL, 0x000000000000003FL, 0x000000000000007FL, 0x00000000000000FFL, 0x00000000000001FFL, 0x00000000000003FFL, 0x00000000000007FFL, 0x0000000000000FFFL, 0x0000000000001FFFL, 0x0000000000003FFFL, 0x0000000000007FFFL, 0x000000000000FFFFL, 0x000000000001FFFFL, 0x000000000003FFFFL, 0x000000000007FFFFL, 0x00000000000FFFFFL, 0x00000000001FFFFFL, 0x00000000003FFFFFL, 0x00000000007FFFFFL, 0x0000000000FFFFFFL, 0x0000000001FFFFFFL, 0x0000000003FFFFFFL, 0x0000000007FFFFFFL, 0x000000000FFFFFFFL, 0x000000001FFFFFFFL, 0x000000003FFFFFFFL, 0x000000007FFFFFFFL, 0x00000000FFFFFFFFL, 0x00000001FFFFFFFFL, 0x00000003FFFFFFFFL, 0x00000007FFFFFFFFL, 0x0000000FFFFFFFFFL, 0x0000001FFFFFFFFFL, 0x0000003FFFFFFFFFL, 0x0000007FFFFFFFFFL, 0x000000FFFFFFFFFFL, 0x000001FFFFFFFFFFL, 0x000003FFFFFFFFFFL, 0x000007FFFFFFFFFFL, 0x00000FFFFFFFFFFFL, 0x00001FFFFFFFFFFFL, 0x00003FFFFFFFFFFFL, 0x00007FFFFFFFFFFFL, 0x0000FFFFFFFFFFFFL, 0x0001FFFFFFFFFFFFL, 0x0003FFFFFFFFFFFFL, 0x0007FFFFFFFFFFFFL, 0x000FFFFFFFFFFFFFL, 0x001FFFFFFFFFFFFFL, 0x003FFFFFFFFFFFFFL, 0x007FFFFFFFFFFFFFL, 0x00FFFFFFFFFFFFFFL, 0x01FFFFFFFFFFFFFFL, 0x03FFFFFFFFFFFFFFL, 0x07FFFFFFFFFFFFFFL, 0x0FFFFFFFFFFFFFFFL, 0x1FFFFFFFFFFFFFFFL, 0x3FFFFFFFFFFFFFFFL, 0x7FFFFFFFFFFFFFFFL, unchecked((long) 0xFFFFFFFFFFFFFFFFL)};

		// mIBy64[j * 16 + i] = (j * 16 + i)/64
		// i =
		// 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		//
		private static readonly int[] mIBY64 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};

		/// <summary>
		///     holds the value of mDeg % MAXLONG.
		/// </summary>
		private readonly int mBit;

		/// <summary>
		///     holds the lenght of the polynomial with 64 bit sized fields.
		/// </summary>
		private readonly int mLength;

		/// <summary>
		///     holds this element in ONB representation.
		/// </summary>
		private long[] mPol;

		// /////////////////////////////////////////////////////////////////////
		// constructors
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Construct a random element over the field <tt>gf2n</tt>, using the
		///     specified source of randomness.
		/// </summary>
		/// <param name="gf2n"> the field </param>
		/// <param name="rand"> the source of randomness </param>
		public GF2nONBElement(GF2nONBField gf2n, SecureRandom rand) {
			this.mField  = gf2n;
			this.mDegree = this.mField.Degree;
			this.mLength = gf2n.ONBLength;
			this.mBit    = gf2n.ONBBit;
			this.mPol    = new long[this.mLength];

			if(this.mLength > 1) {
				for(int j = 0; j < (this.mLength - 1); j++) {
					this.mPol[j] = rand.NextLong();
				}

				long last = rand.NextLong();
				this.mPol[this.mLength - 1] = (long) ((ulong) last >> (MAXLONG - this.mBit));
			} else {
				this.mPol[0] = rand.NextLong();
				this.mPol[0] = (long) ((ulong) this.mPol[0] >> (MAXLONG - this.mBit));
			}
		}

		/// <summary>
		///     Construct a new GF2nONBElement from its encoding.
		/// </summary>
		/// <param name="gf2n"> the field </param>
		/// <param name="e">    the encoded element </param>
		public GF2nONBElement(GF2nONBField gf2n, SafeArrayHandle e) {
			this.mField  = gf2n;
			this.mDegree = this.mField.Degree;
			this.mLength = gf2n.ONBLength;
			this.mBit    = gf2n.ONBBit;
			this.mPol    = new long[this.mLength];
			this.assign(e);
		}

		/// <summary>
		///     Construct the element of the field <tt>gf2n</tt> with the specified
		///     value <tt>val</tt>.
		/// </summary>
		/// <param name="gf2n"> the field </param>
		/// <param name="val">  the value represented by a BigInteger </param>
		public GF2nONBElement(GF2nONBField gf2n, BigInteger val) {
			this.mField  = gf2n;
			this.mDegree = this.mField.Degree;
			this.mLength = gf2n.ONBLength;
			this.mBit    = gf2n.ONBBit;
			this.mPol    = new long[this.mLength];
			this.assign(val);
		}

		/// <summary>
		///     Construct the element of the field <tt>gf2n</tt> with the specified
		///     value <tt>val</tt>.
		/// </summary>
		/// <param name="gf2n"> the field </param>
		/// <param name="val">  the value in ONB representation </param>
		private GF2nONBElement(GF2nONBField gf2n, long[] val) {
			this.mField  = gf2n;
			this.mDegree = this.mField.Degree;
			this.mLength = gf2n.ONBLength;
			this.mBit    = gf2n.ONBBit;
			this.mPol    = val;
		}

		// /////////////////////////////////////////////////////////////////////
		// pseudo-constructors
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Copy constructor.
		/// </summary>
		/// <param name="gf2n"> the field </param>
		public GF2nONBElement(GF2nONBElement gf2n) {

			this.mField  = gf2n.mField;
			this.mDegree = this.mField.Degree;
			this.mLength = ((GF2nONBField) this.mField).ONBLength;
			this.mBit    = ((GF2nONBField) this.mField).ONBBit;
			this.mPol    = new long[this.mLength];
			this.assign(gf2n.Element);
		}

		// /////////////////////////////////////////////////////////////////
		// comparison
		// /////////////////////////////////////////////////////////////////

		/// <summary>
		///     Checks whether this element is zero.
		/// </summary>
		/// <returns> <tt>true</tt> if <tt>this</tt> is the zero element </returns>
		public override bool Zero {
			get {

				bool result = true;

				for(int i = 0; (i < this.mLength) && result; i++) {
					result = result && (((ulong) this.mPol[i] & 0xFFFFFFFFFFFFFFFFL) == 0);
				}

				return result;
			}
		}

		/// <summary>
		///     Checks whether this element is one.
		/// </summary>
		/// <returns> <tt>true</tt> if <tt>this</tt> is the one element </returns>
		public override bool One {
			get {

				bool result = true;

				for(int i = 0; (i < (this.mLength - 1)) && result; i++) {
					result = result && (((ulong) this.mPol[i] & 0xFFFFFFFFFFFFFFFFL) == 0xFFFFFFFFFFFFFFFFL);
				}

				if(result) {
					result = result && ((this.mPol[this.mLength - 1] & mMaxmask[this.mBit - 1]) == mMaxmask[this.mBit - 1]);
				}

				return result;
			}
		}

		/// <returns> this element in its ONB representation </returns>
		private long[] Element {
			get {

				long[] result = new long[this.mPol.Length];
				Array.Copy(this.mPol, 0, result, 0, this.mPol.Length);

				return result;
			}
		}

		/// <summary>
		///     Returns the ONB representation of this element. The Bit-Order is
		///     exchanged (according to 1363)!
		/// </summary>
		/// <returns> this element in its representation and reverse bit-order </returns>
		private long[] ElementReverseOrder {
			get {
				long[] result = new long[this.mPol.Length];

				for(int i = 0; i < this.mDegree; i++) {
					if(this.testBit(this.mDegree - i - 1)) {
						result[(int) ((uint) i >> 6)] |= mBitmask[i & 0x3f];
					}
				}

				return result;
			}
		}

		/// <summary>
		///     Create a new GF2nONBElement by cloning this GF2nPolynomialElement.
		/// </summary>
		/// <returns> a copy of this element </returns>
		public override object clone() {
			return new GF2nONBElement(this);
		}

		/// <summary>
		///     Create the zero element.
		/// </summary>
		/// <param name="gf2n"> the finite field </param>
		/// <returns> the zero element in the given finite field </returns>
		public static GF2nONBElement ZERO(GF2nONBField gf2n) {
			long[] polynomial = new long[gf2n.ONBLength];

			return new GF2nONBElement(gf2n, polynomial);
		}

		/// <summary>
		///     Create the one element.
		/// </summary>
		/// <param name="gf2n"> the finite field </param>
		/// <returns> the one element in the given finite field </returns>
		public static GF2nONBElement ONE(GF2nONBField gf2n) {
			int    mLength    = gf2n.ONBLength;
			long[] polynomial = new long[mLength];

			// fill mDegree coefficients with one's
			for(int i = 0; i < (mLength - 1); i++) {
				polynomial[i] = unchecked((long) 0xffffffffffffffffL);
			}

			polynomial[mLength - 1] = mMaxmask[gf2n.ONBBit - 1];

			return new GF2nONBElement(gf2n, polynomial);
		}

		// /////////////////////////////////////////////////////////////////////
		// assignments
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     assigns to this element the zero element
		/// </summary>
		internal override void assignZero() {
			this.mPol = new long[this.mLength];
		}

		/// <summary>
		///     assigns to this element the one element
		/// </summary>
		internal override void assignOne() {
			// fill mDegree coefficients with one's
			for(int i = 0; i < (this.mLength - 1); i++) {
				this.mPol[i] = unchecked((long) 0xffffffffffffffffL);
			}

			this.mPol[this.mLength - 1] = mMaxmask[this.mBit - 1];
		}

		/// <summary>
		///     assigns to this element the value <tt>val</tt>.
		/// </summary>
		/// <param name="val"> the value represented by a BigInteger </param>
		private void assign(BigInteger val) {
			this.assign(val.ToByteArray());
		}

		/// <summary>
		///     assigns to this element the value <tt>val</tt>.
		/// </summary>
		/// <param name="val"> the value in ONB representation </param>
		private void assign(long[] val) {
			Array.Copy(val, 0, this.mPol, 0, this.mLength);
		}

		/// <summary>
		///     assigns to this element the value <tt>val</tt>. First: inverting the
		///     order of val into reversed[]. That means: reversed[0] = val[length - 1],
		///     ..., reversed[reversed.length - 1] = val[0]. Second: mPol[0] = sum{i = 0,
		///     ... 7} (val[i]<<(i*8)) .... mPol[1]= sum{ i= 8, ... 15} ( val[ i]<<(i*8))
		/// </summary>
		/// <param name="val"> the value in ONB representation </param>
		private void assign(SafeArrayHandle val) {
			int j;
			this.mPol = new long[this.mLength];

			for(j = 0; j < val.Length; j++) {
				this.mPol[(int) ((uint) j >> 3)] |= (val[val.Length - 1 - j] & 0x00000000000000ffL) << ((j & 0x07) << 3);
			}
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
			if((other == null) || !(other is GF2nONBElement)) {
				return false;
			}

			GF2nONBElement otherElem = (GF2nONBElement) other;

			for(int i = 0; i < this.mLength; i++) {
				if(this.mPol[i] != otherElem.mPol[i]) {
					return false;
				}
			}

			return true;
		}

		/// <returns> the hash code of this element </returns>
		public override int GetHashCode() {
			return this.mPol.GetHashCode();
		}

		// /////////////////////////////////////////////////////////////////////
		// access
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns whether the highest bit of the bit representation is set
		/// </summary>
		/// <returns> true, if the highest bit of mPol is set, false, otherwise </returns>
		public override bool testRightmostBit() {
			// due to the reverse bit order (compared to 1363) this method returns
			// the value of the leftmost bit
			return (this.mPol[this.mLength - 1] & mBitmask[this.mBit - 1]) != 0L;
		}

		/// <summary>
		///     Checks whether the indexed bit of the bit representation is set. Warning:
		///     GF2nONBElement currently stores its bits in reverse order (compared to
		///     1363) !!!
		/// </summary>
		/// <param name="index"> the index of the bit to test </param>
		/// <returns>
		///     <tt>true</tt> if the indexed bit of mPol is set, <tt>false</tt>
		///     otherwise.
		/// </returns>
		internal override bool testBit(int index) {
			if((index < 0) || (index > this.mDegree)) {
				return false;
			}

			long test = this.mPol[(int) ((uint) index >> 6)] & mBitmask[index & 0x3f];

			return test != 0x0L;
		}

		/// <summary>
		///     Reverses the bit-order in this element(according to 1363). This is a
		///     hack!
		/// </summary>
		internal virtual void reverseOrder() {
			this.mPol = this.ElementReverseOrder;
		}

		// /////////////////////////////////////////////////////////////////////
		// arithmetic
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Compute the sum of this element and <tt>addend</tt>.
		/// </summary>
		/// <param name="addend"> the addend </param>
		/// <returns> <tt>this + other</tt> (newly created) </returns>
		public override GFElement add(GFElement addend) {
			GF2nONBElement result = new GF2nONBElement(this);
			result.addToThis(addend);

			return result;
		}

		/// <summary>
		///     Compute <tt>this + addend</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="addend"> the addend </param>
		public override void addToThis(GFElement addend) {
			if(!(addend is GF2nONBElement)) {
				throw new Exception();
			}

			if(!this.mField.Equals(((GF2nONBElement) addend).mField)) {
				throw new Exception();
			}

			for(int i = 0; i < this.mLength; i++) {
				this.mPol[i] ^= ((GF2nONBElement) addend).mPol[i];
			}
		}

		/// <summary>
		///     returns <tt>this</tt> element + 1.
		/// </summary>
		/// <returns> <tt>this</tt> + 1 </returns>
		public override GF2nElement increase() {
			GF2nONBElement result = new GF2nONBElement(this);
			result.increaseThis();

			return result;
		}

		/// <summary>
		///     increases <tt>this</tt> element.
		/// </summary>
		public override void increaseThis() {
			this.addToThis(ONE((GF2nONBField) this.mField));
		}

		/// <summary>
		///     Compute the product of this element and <tt>factor</tt>.
		/// </summary>
		/// <param name="factor"> the factor </param>
		/// <returns> <tt>this * factor</tt> (newly created) </returns>
		public override GFElement multiply(GFElement factor) {
			GF2nONBElement result = new GF2nONBElement(this);
			result.multiplyThisBy(factor);

			return result;
		}

		/// <summary>
		///     Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
		/// </summary>
		/// <param name="factor"> the factor </param>
		public override void multiplyThisBy(GFElement factor) {

			if(!(factor is GF2nONBElement)) {
				throw new Exception("The elements have different" + " representation: not yet" + " implemented");
			}

			if(!this.mField.Equals(((GF2nONBElement) factor).mField)) {
				throw new Exception();
			}

			if(this.Equals(factor)) {
				this.squareThis();
			} else {

				long[] a = this.mPol;
				long[] b = ((GF2nONBElement) factor).mPol;
				long[] c = new long[this.mLength];

				int[][] m = ((GF2nONBField) this.mField).mMult;

				int degf, degb, s, fielda, fieldb, bita, bitb;
				degf = this.mLength - 1;
				degb = this.mBit    - 1;
				s    = 0;

				long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
				long TWOTODEGB      = mBitmask[degb];

				bool old, now;

				// the product c of a and b (a*b = c) is calculated in mDegree
				// cicles
				// in every cicle one coefficient of c is calculated and stored
				// k indicates the coefficient
				//
				for(int k = 0; k < this.mDegree; k++) {

					s = 0;

					for(int i = 0; i < this.mDegree; i++) {

						// fielda = i / MAXLONG
						//
						fielda = mIBY64[i];

						// bita = i % MAXLONG
						//
						bita = i & (MAXLONG - 1);

						// fieldb = m[i][0] / MAXLONG
						//
						fieldb = mIBY64[m[i][0]];

						// bitb = m[i][0] % MAXLONG
						//
						bitb = m[i][0] & (MAXLONG - 1);

						if((a[fielda] & mBitmask[bita]) != 0) {

							if((b[fieldb] & mBitmask[bitb]) != 0) {
								s ^= 1;
							}

							if(m[i][1] != -1) {

								// fieldb = m[i][1] / MAXLONG
								//
								fieldb = mIBY64[m[i][1]];

								// bitb = m[i][1] % MAXLONG
								//
								bitb = m[i][1] & (MAXLONG - 1);

								if((b[fieldb] & mBitmask[bitb]) != 0) {
									s ^= 1;
								}

							}
						}
					}

					fielda = mIBY64[k];
					bita   = k & (MAXLONG - 1);

					if(s != 0) {
						c[fielda] ^= mBitmask[bita];
					}

					// Circular shift of x and y one bit to the right,
					// respectively.

					if(this.mLength > 1) {

						// Shift x.
						//
						old = (a[degf] & 1) == 1;

						for(int i = degf - 1; i >= 0; i--) {
							now = (a[i] & 1) != 0;

							a[i] = (long) ((ulong) a[i] >> 1);

							if(old) {
								a[i] ^= TWOTOMAXLONGM1;
							}

							old = now;
						}

						a[degf] = (long) ((ulong) a[degf] >> 1);

						if(old) {
							a[degf] ^= TWOTODEGB;
						}

						// Shift y.
						//
						old = (b[degf] & 1) == 1;

						for(int i = degf - 1; i >= 0; i--) {
							now = (b[i] & 1) != 0;

							b[i] = (long) ((ulong) b[i] >> 1);

							if(old) {
								b[i] ^= TWOTOMAXLONGM1;
							}

							old = now;
						}

						b[degf] = (long) ((ulong) b[degf] >> 1);

						if(old) {
							b[degf] ^= TWOTODEGB;
						}
					} else {
						old  = (a[0] & 1) == 1;
						a[0] = (long) ((ulong) a[0] >> 1);

						if(old) {
							a[0] ^= TWOTODEGB;
						}

						old  = (b[0] & 1) == 1;
						b[0] = (long) ((ulong) b[0] >> 1);

						if(old) {
							b[0] ^= TWOTODEGB;
						}
					}
				}

				this.assign(c);
			}
		}

		/// <summary>
		///     returns <tt>this</tt> element to the power of 2.
		/// </summary>
		/// <returns>
		///     <tt>this</tt><sup>2</sup>
		/// </returns>
		public override GF2nElement square() {
			GF2nONBElement result = new GF2nONBElement(this);
			result.squareThis();

			return result;
		}

		/// <summary>
		///     squares <tt>this</tt> element.
		/// </summary>
		public override void squareThis() {

			long[] pol = this.Element;

			int f = this.mLength - 1;
			int b = this.mBit    - 1;

			// Shift the coefficients one bit to the left.
			//
			long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
			bool old, now;

			old = (pol[f] & mBitmask[b]) != 0;

			for(int i = 0; i < f; i++) {

				now = (pol[i] & TWOTOMAXLONGM1) != 0;

				pol[i] = pol[i] << 1;

				if(old) {
					pol[i] ^= 1;
				}

				old = now;
			}

			now = (pol[f] & mBitmask[b]) != 0;

			pol[f] = pol[f] << 1;

			if(old) {
				pol[f] ^= 1;
			}

			// Set the bit with index mDegree to zero.
			//
			if(now) {
				pol[f] ^= mBitmask[b + 1];
			}

			this.assign(pol);
		}

		/// <summary>
		///     Compute the multiplicative inverse of this element.
		/// </summary>
		/// <returns> <tt>this<sup>-1</sup></tt> (newly created) </returns>
		/// <exception cref="ArithmeticException"> if <tt>this</tt> is the zero element. </exception>
		public override GFElement invert() {
			GF2nONBElement result = new GF2nONBElement(this);
			result.invertThis();

			return result;
		}

		/// <summary>
		///     Multiplicatively invert of this element (overwrite <tt>this</tt>).
		/// </summary>
		/// <exception cref="ArithmeticException"> if <tt>this</tt> is the zero element. </exception>
		public virtual void invertThis() {

			if(this.Zero) {
				throw new ArithmeticException();
			}

			int r = 31; // mDegree kann nur 31 Bits lang sein!!!

			// Bitlaenge von mDegree:
			for(bool found = false; !found && (r >= 0); r--) {

				if(((this.mDegree - 1) & mBitmask[r]) != 0) {
					found = true;
				}
			}

			r++;

			GF2nElement m = ZERO((GF2nONBField) this.mField);
			GF2nElement n = new GF2nONBElement(this);

			int k = 1;

			for(int i = r - 1; i >= 0; i--) {
				m = (GF2nElement) n.clone();

				for(int j = 1; j <= k; j++) {
					m.squareThis();
				}

				n.multiplyThisBy(m);

				k <<= 1;

				if(((this.mDegree - 1) & mBitmask[i]) != 0) {
					n.squareThis();

					n.multiplyThisBy(this);

					k++;
				}
			}

			n.squareThis();
		}

		/// <summary>
		///     returns the root of<tt>this</tt> element.
		/// </summary>
		/// <returns>
		///     <tt>this</tt><sup>1/2</sup>
		/// </returns>
		public override GF2nElement squareRoot() {
			GF2nONBElement result = new GF2nONBElement(this);
			result.squareRootThis();

			return result;
		}

		/// <summary>
		///     square roots <tt>this</tt> element.
		/// </summary>
		public override void squareRootThis() {

			long[] pol = this.Element;

			int f = this.mLength - 1;
			int b = this.mBit    - 1;

			// Shift the coefficients one bit to the right.
			//
			long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
			bool old, now;

			old = (pol[0] & 1) != 0;

			for(int i = f; i >= 0; i--) {
				now    = (pol[i] & 1) != 0;
				pol[i] = (long) ((ulong) pol[i] >> 1);

				if(old) {
					if(i == f) {
						pol[i] ^= mBitmask[b];
					} else {
						pol[i] ^= TWOTOMAXLONGM1;
					}
				}

				old = now;
			}

			this.assign(pol);
		}

		/// <summary>
		///     Returns the trace of this element.
		/// </summary>
		/// <returns> the trace of this element </returns>
		public override int trace() {

			// trace = sum of coefficients
			//

			int result = 0;

			int max = this.mLength - 1;

			for(int i = 0; i < max; i++) {

				for(int j = 0; j < MAXLONG; j++) {

					if((this.mPol[i] & mBitmask[j]) != 0) {
						result ^= 1;
					}
				}
			}

			int b = this.mBit;

			for(int j = 0; j < b; j++) {

				if((this.mPol[max] & mBitmask[j]) != 0) {
					result ^= 1;
				}
			}

			return result;
		}

		/// <summary>
		///     Solves a quadratic equation.
		///     <br>
		///         Let z<sup>2</sup> + z = <tt>this</tt>. Then this method returns z.
		/// </summary>
		/// <returns> z with z<sup>2</sup> + z = <tt>this</tt> </returns>
		public override GF2nElement solveQuadraticEquation() {

			if(this.trace() == 1) {
				throw new Exception();
			}

			long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
			long ZERO           = 0L;
			long ONE            = 1L;

			long[] p = new long[this.mLength];
			long   z = 0L;
			int    j = 1;

			for(int i = 0; i < (this.mLength - 1); i++) {

				for(j = 1; j < MAXLONG; j++) {

					//
					if(!((((mBitmask[j] & this.mPol[i]) != ZERO) && ((z & mBitmask[j - 1]) != ZERO)) || (((this.mPol[i] & mBitmask[j]) == ZERO) && ((z & mBitmask[j - 1]) == ZERO)))) {
						z ^= mBitmask[j];
					}
				}

				p[i] = z;

				if((((TWOTOMAXLONGM1 & z) != ZERO) && ((ONE & this.mPol[i + 1]) == ONE)) || (((TWOTOMAXLONGM1 & z) == ZERO) && ((ONE & this.mPol[i + 1]) == ZERO))) {
					z = ZERO;
				} else {
					z = ONE;
				}
			}

			int b = this.mDegree & (MAXLONG - 1);

			long LASTLONG = this.mPol[this.mLength - 1];

			for(j = 1; j < b; j++) {
				if(!((((mBitmask[j] & LASTLONG) != ZERO) && ((mBitmask[j - 1] & z) != ZERO)) || (((mBitmask[j] & LASTLONG) == ZERO) && ((mBitmask[j - 1] & z) == ZERO)))) {
					z ^= mBitmask[j];
				}
			}

			p[this.mLength - 1] = z;

			return new GF2nONBElement((GF2nONBField) this.mField, p);
		}

		// /////////////////////////////////////////////////////////////////
		// conversion
		// /////////////////////////////////////////////////////////////////

		/// <summary>
		///     Returns a String representation of this element.
		/// </summary>
		/// <returns> String representation of this element with the specified radix </returns>
		public override string ToString() {
			return this.ToString(16);
		}

		/// <summary>
		///     Returns a String representation of this element. <tt>radix</tt>
		///     specifies the radix of the String representation.
		///     <br>
		///         NOTE: ONLY <tt>radix = 2</tt> or <tt>radix = 16</tt> IS IMPLEMENTED
		/// </summary>
		/// <param name="radix"> specifies the radix of the String representation </param>
		/// <returns> String representation of this element with the specified radix </returns>
		public override string ToString(int radix) {
			string s = "";

			long[] a = this.Element;
			int    b = this.mBit;

			if(radix == 2) {

				for(int j = b - 1; j >= 0; j--) {
					if((a[a.Length - 1] & ((long) 1 << j)) == 0) {
						s += "0";
					} else {
						s += "1";
					}
				}

				for(int i = a.Length - 2; i >= 0; i--) {
					for(int j = MAXLONG - 1; j >= 0; j--) {
						if((a[i] & mBitmask[j]) == 0) {
							s += "0";
						} else {
							s += "1";
						}
					}
				}
			} else if(radix == 16) {

				char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

				for(int i = a.Length - 1; i >= 0; i--) {
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 60) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 56) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 52) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 48) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 44) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 40) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 36) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 32) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 28) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 24) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 20) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 16) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 12) & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 8)  & 0x0f];
					s += HEX_CHARS[(int) (long) ((ulong) a[i] >> 4)  & 0x0f];
					s += HEX_CHARS[(int) a[i]                        & 0x0f];
					s += " ";
				}
			}

			return s;
		}

		/// <summary>
		///     Returns this element as FlexiBigInt. The conversion is <a href="http://grouper.ieee.org/groups/1363/">P1363</a>
		///     -conform.
		/// </summary>
		/// <returns> this element as BigInteger </returns>
		public override BigInteger toFlexiBigInt() {
			/// <summary>
			/// @todo this method does not reverse the bit-order as it should!!! </summary>

			return new BigInteger(1, this.toByteArray());
		}

		/// <summary>
		///     Returns this element as byte array. The conversion is <a href="http://grouper.ieee.org/groups/1363/">P1363</a>
		///     -conform.
		/// </summary>
		/// <returns> this element as byte array </returns>
		public override SafeArrayHandle toByteArray() {
			/// <summary>
			/// @todo this method does not reverse the bit-order as it should!!! </summary>

			int         k      = ((this.mDegree - 1) >> 3) + 1;
			SafeArrayHandle result = ByteArray.Create(k);
			int         i;

			for(i = 0; i < k; i++) {
				result[k - i - 1] = (byte) (long) ((ulong) (this.mPol[(int) ((uint) i >> 3)] & (0x00000000000000ffL << ((i & 0x07) << 3))) >> ((i & 0x07) << 3));
			}

			return result;
		}
	}

}
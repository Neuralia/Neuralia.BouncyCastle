using System;
using System.Text;
using Neuralia.Blockchains.Tools.Data;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements the abstract class <tt>Vector</tt> for the case of
	///     vectors over the finite field GF(2).
	///     <br>
	///         For the vector representation the array of type int[] is used, thus one
	///         element of the array holds 32 elements of the vector.
	/// </summary>
	/// <seealso cref= Vector
	/// </seealso>
	public class GF2Vector : Vector {

		/// <summary>
		///     holds the elements of this vector
		/// </summary>
		private readonly int[] v;

		/// <summary>
		///     Construct the zero vector of the given length.
		/// </summary>
		/// <param name="length"> the length of the vector </param>
		public GF2Vector(int length) {
			if(length < 0) {
				throw new ArithmeticException("Negative length.");
			}

			this.length = length;
			this.v      = new int[(length + 31) >> 5];
		}

		/// <summary>
		///     Construct a random GF2Vector of the given length.
		/// </summary>
		/// <param name="length"> the length of the vector </param>
		/// <param name="sr">     the source of randomness </param>
		public GF2Vector(int length, SecureRandom sr) {
			this.length = length;

			int size = (length + 31) >> 5;
			this.v = new int[size];

			// generate random elements
			for(int i = size - 1; i >= 0; i--) {
				this.v[i] = sr.Next();
			}

			// erase unused bits
			int r = length & 0x1f;

			if(r != 0) {
				// erase unused bits
				this.v[size - 1] &= (1 << r) - 1;
			}
		}

		/// <summary>
		///     Construct a random GF2Vector of the given length with the specified
		///     number of non-zero coefficients.
		/// </summary>
		/// <param name="length"> the length of the vector </param>
		/// <param name="t">      the number of non-zero coefficients </param>
		/// <param name="sr">     the source of randomness </param>
		public GF2Vector(int length, int t, SecureRandom sr) {
			if(t > length) {
				throw new ArithmeticException("The hamming weight is greater than the length of vector.");
			}

			this.length = length;

			int size = (length + 31) >> 5;
			this.v = new int[size];

			int[] help = new int[length];

			for(int i = 0; i < length; i++) {
				help[i] = i;
			}

			int m = length;

			for(int i = 0; i < t; i++) {
				int j = RandUtils.nextInt(sr, m);
				this.Bit = help[j];
				m--;
				help[j] = help[m];
			}
		}

		/// <summary>
		///     Construct a GF2Vector of the given length and with elements from the
		///     given array. The array is copied and unused bits are masked out.
		/// </summary>
		/// <param name="length"> the length of the vector </param>
		/// <param name="v">      the element array </param>
		public GF2Vector(int length, int[] v) {
			if(length < 0) {
				throw new ArithmeticException("negative length");
			}

			this.length = length;

			int size = (length + 31) >> 5;

			if(v.Length != size) {
				throw new ArithmeticException("length mismatch");
			}

			this.v = IntUtils.clone(v);

			int r = length & 0x1f;

			if(r != 0) {
				// erase unused bits
				this.v[size - 1] &= (1 << r) - 1;
			}
		}

		/// <summary>
		///     Copy constructor.
		/// </summary>
		/// <param name="other"> another <seealso cref="GF2Vector" /> </param>
		public GF2Vector(GF2Vector other) {
			this.length = other.length;
			this.v      = IntUtils.clone(other.v);
		}

		/// <summary>
		///     Construct a new <seealso cref="GF2Vector" /> of the given length and with the given
		///     element array. The array is not changed and only a reference to the array
		///     is stored. No length checking is performed either.
		/// </summary>
		/// <param name="v">      the element array </param>
		/// <param name="length"> the length of the vector </param>
		protected internal GF2Vector(int[] v, int length) {
			this.v      = v;
			this.length = length;
		}

		/// <summary>
		///     Encode this vector as byte array.
		/// </summary>
		/// <returns> the encoded vector </returns>
		public override SafeArrayHandle Encoded {
			get {
				int byteLen = (this.length + 7) >> 3;

				return LittleEndianConversions.toByteArray(this.v, byteLen);
			}
		}

		/// <returns> the int array representation of this vector </returns>
		public virtual int[] VecArray => this.v;

		/// <summary>
		///     Return the Hamming weight of this vector, i.e., compute the number of
		///     units of this vector.
		/// </summary>
		/// <returns> the Hamming weight of this vector </returns>
		public virtual int HammingWeight {
			get {
				int weight = 0;

				for(int i = 0; i < this.v.Length; i++) {
					int e = this.v[i];

					for(int j = 0; j < 32; j++) {
						int b = e & 1;

						if(b != 0) {
							weight++;
						}

						e = (int) ((uint) e >> 1);
					}
				}

				return weight;
			}
		}

		/// <returns> whether this is the zero vector (i.e., all elements are zero) </returns>
		public override bool Zero {
			get {
				for(int i = this.v.Length - 1; i >= 0; i--) {
					if(this.v[i] != 0) {
						return false;
					}
				}

				return true;
			}
		}

		/// <summary>
		///     Set the coefficient at the given index to 1. If the index is out of
		///     bounds, do nothing.
		/// </summary>
		/// <param name="index"> the index of the coefficient to set </param>
		public virtual int Bit {
			set {
				if(value >= this.length) {
					throw new IndexOutOfRangeException();
				}

				this.v[value >> 5] |= 1 << (value & 0x1f);
			}
		}

		/// <summary>
		///     Construct a new GF2Vector with the given length out of the encoded
		///     vector.
		/// </summary>
		/// <param name="length"> the length of the vector </param>
		/// <param name="encVec"> the encoded vector </param>
		/// <returns> the decoded vector </returns>
		public static GF2Vector OS2VP(int length, SafeArrayHandle encVec) {
			if(length < 0) {
				throw new ArithmeticException("negative length");
			}

			int byteLen = (length + 7) >> 3;

			if(encVec.Length > byteLen) {
				throw new ArithmeticException("length mismatch");
			}

			return new GF2Vector(length, LittleEndianConversions.toIntArray(encVec));
		}

		/// <summary>
		///     Return the value of the bit of this vector at the specified index.
		/// </summary>
		/// <param name="index"> the index </param>
		/// <returns> the value of the bit (0 or 1) </returns>
		public virtual int getBit(int index) {
			if(index >= this.length) {
				throw new IndexOutOfRangeException();
			}

			int q = index >> 5;
			int r = index & 0x1f;

			return (int) ((uint) (this.v[q] & (1 << r)) >> r);
		}

		/// <summary>
		///     Adds another GF2Vector to this vector.
		/// </summary>
		/// <param name="other"> another GF2Vector </param>
		/// <returns>
		///     <tt>this + other</tt>
		/// </returns>
		/// <exception cref="ArithmeticException">
		///     if the other vector is not a GF2Vector or has another
		///     length.
		/// </exception>
		public override Vector add(Vector other) {
			if(!(other is GF2Vector)) {
				throw new ArithmeticException("vector is not defined over GF(2)");
			}

			GF2Vector otherVec = (GF2Vector) other;

			if(this.length != otherVec.length) {
				throw new ArithmeticException("length mismatch");
			}

			int[] vec = IntUtils.clone(((GF2Vector) other).v);

			for(int i = vec.Length - 1; i >= 0; i--) {
				vec[i] ^= this.v[i];
			}

			return new GF2Vector(this.length, vec);
		}

		/// <summary>
		///     Multiply this vector with a permutation.
		/// </summary>
		/// <param name="p"> the permutation </param>
		/// <returns>
		///     <tt>this*p = p*this</tt>
		/// </returns>
		public override Vector multiply(Permutation p) {
			int[] pVec = p.Vector;

			if(this.length != pVec.Length) {
				throw new ArithmeticException("length mismatch");
			}

			GF2Vector result = new GF2Vector(this.length);

			for(int i = 0; i < pVec.Length; i++) {
				int e = this.v[pVec[i] >> 5] & (1 << (pVec[i] & 0x1f));

				if(e != 0) {
					result.v[i >> 5] |= 1 << (i & 0x1f);
				}
			}

			return result;
		}

		/// <summary>
		///     Return a new vector consisting of the elements of this vector with the
		///     indices given by the set <tt>setJ</tt>.
		/// </summary>
		/// <param name="setJ"> the set of indices of elements to extract </param>
		/// <returns>
		///     the new <seealso cref="GF2Vector" />
		///     <tt>[this_setJ[0], this_setJ[1], ..., this_setJ[#setJ-1]]</tt>
		/// </returns>
		public virtual GF2Vector extractVector(int[] setJ) {
			int k = setJ.Length;

			if(setJ[k - 1] > this.length) {
				throw new ArithmeticException("invalid index set");
			}

			GF2Vector result = new GF2Vector(k);

			for(int i = 0; i < k; i++) {
				int e = this.v[setJ[i] >> 5] & (1 << (setJ[i] & 0x1f));

				if(e != 0) {
					result.v[i >> 5] |= 1 << (i & 0x1f);
				}
			}

			return result;
		}

		/// <summary>
		///     Return a new vector consisting of the first <tt>k</tt> elements of this
		///     vector.
		/// </summary>
		/// <param name="k"> the number of elements to extract </param>
		/// <returns>
		///     a new <seealso cref="GF2Vector" /> consisting of the first <tt>k</tt>
		///     elements of this vector
		/// </returns>
		public virtual GF2Vector extractLeftVector(int k) {
			if(k > this.length) {
				throw new ArithmeticException("invalid length");
			}

			if(k == this.length) {
				return new GF2Vector(this);
			}

			GF2Vector result = new GF2Vector(k);

			int q = k >> 5;
			int r = k & 0x1f;

			Array.Copy(this.v, 0, result.v, 0, q);

			if(r != 0) {
				result.v[q] = this.v[q] & ((1 << r) - 1);
			}

			return result;
		}

		/// <summary>
		///     Return a new vector consisting of the last <tt>k</tt> elements of this
		///     vector.
		/// </summary>
		/// <param name="k"> the number of elements to extract </param>
		/// <returns>
		///     a new <seealso cref="GF2Vector" /> consisting of the last <tt>k</tt>
		///     elements of this vector
		/// </returns>
		public virtual GF2Vector extractRightVector(int k) {
			if(k > this.Length) {
				throw new ArithmeticException("invalid length");
			}

			if(k == this.Length) {
				return new GF2Vector(this);
			}

			GF2Vector result = new GF2Vector(k);

			int q      = (this.Length - k) >> 5;
			int r      = (this.Length - k) & 0x1f;
			int length = (k           + 31) >> 5;

			int ind = q;

			// if words have to be shifted
			if(r != 0) {
				// process all but last word
				for(int i = 0; i < (length - 1); i++) {
					result.v[i] = (int) ((uint) this.v[ind++] >> r) | (this.v[ind] << (32 - r));
				}

				// process last word
				result.v[length - 1] = (int) ((uint) this.v[ind++] >> r);

				if(ind < this.v.Length) {
					result.v[length - 1] |= this.v[ind] << (32 - r);
				}
			} else {
				// no shift necessary
				Array.Copy(this.v, q, result.v, 0, length);
			}

			return result;
		}

		/// <summary>
		///     Rewrite this vector as a vector over <tt>GF(2<sup>m</sup>)</tt> with
		///     <tt>t</tt> elements.
		/// </summary>
		/// <param name="field"> the finite field <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <returns> the converted vector over <tt>GF(2<sup>m</sup>)</tt> </returns>
		public virtual GF2mVector toExtensionFieldVector(GF2mField field) {
			int m = field.Degree;

			if((this.length % m) != 0) {
				throw new ArithmeticException("conversion is impossible");
			}

			int   t      = this.length / m;
			int[] result = new int[t];
			int   count  = 0;

			for(int i = t - 1; i >= 0; i--) {
				for(int j = field.Degree - 1; j >= 0; j--) {
					int q = (int) ((uint) count >> 5);
					int r = count & 0x1f;

					int e = (int) ((uint) this.v[q] >> r) & 1;

					if(e == 1) {
						result[i] ^= 1 << j;
					}

					count++;
				}
			}

			return new GF2mVector(field, result);
		}

		/// <summary>
		///     Check if the given object is equal to this vector.
		/// </summary>
		/// <param name="other"> vector </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other) {

			if(!(other is GF2Vector)) {
				return false;
			}

			GF2Vector otherVec = (GF2Vector) other;

			return (this.length == otherVec.length) && IntUtils.Equals(this.v, otherVec.v);
		}

		/// <returns> the hash code of this vector </returns>
		public override int GetHashCode() {
			int hash = this.length;
			hash = (hash * 31) + this.v.GetHashCode();

			return hash;
		}

		/// <returns> a human readable form of this vector </returns>
		public override string ToString() {
			StringBuilder buf = new StringBuilder();

			for(int i = 0; i < this.length; i++) {
				if((i != 0) && ((i & 0x1f) == 0)) {
					buf.Append(' ');
				}

				int q   = i >> 5;
				int r   = i         & 0x1f;
				int bit = this.v[q] & (1 << r);

				if(bit == 0) {
					buf.Append('0');
				} else {
					buf.Append('1');
				}
			}

			return buf.ToString();
		}
	}

}
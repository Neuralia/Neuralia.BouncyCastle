using System;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements polynomials over GF2nElements.
	/// </summary>
	/// <seealso cref= GF2nElement
	/// </seealso>
	public class GF2nPolynomial {

		private GF2nElement[] coeff; // keeps the coefficients of this polynomial

		private int size_Renamed; // the size of this polynomial

		/// <summary>
		///     Creates a new PolynomialGF2n of size <i>deg</i> and elem as
		///     coefficients.
		/// </summary>
		/// <param name="deg">
		///     -
		///     the maximum degree + 1
		/// </param>
		/// <param name="elem">
		///     -
		///     a GF2nElement
		/// </param>
		public GF2nPolynomial(int deg, GF2nElement elem) {
			this.size_Renamed = deg;
			this.coeff        = new GF2nElement[this.size_Renamed];

			for(int i = 0; i < this.size_Renamed; i++) {
				this.coeff[i] = (GF2nElement) elem.clone();
			}
		}

		/// <summary>
		///     Creates a new PolynomialGF2n of size <i>deg</i>.
		/// </summary>
		/// <param name="deg"> the maximum degree + 1 </param>
		private GF2nPolynomial(int deg) {
			this.size_Renamed = deg;
			this.coeff        = new GF2nElement[this.size_Renamed];
		}

		/// <summary>
		///     Creates a new PolynomialGF2n by cloning the given PolynomialGF2n <i>a</i>.
		/// </summary>
		/// <param name="a"> the PolynomialGF2n to clone </param>
		public GF2nPolynomial(GF2nPolynomial a) {
			int i;
			this.coeff        = new GF2nElement[a.size_Renamed];
			this.size_Renamed = a.size_Renamed;

			for(i = 0; i < this.size_Renamed; i++) {
				this.coeff[i] = (GF2nElement) a.coeff[i].clone();
			}
		}

		/// <summary>
		///     Creates a new PolynomialGF2n from the given Bitstring <i>polynomial</i>
		///     over the GF2nField <i>B1</i>.
		/// </summary>
		/// <param name="polynomial"> the Bitstring to use </param>
		/// <param name="B1">         the field </param>
		public GF2nPolynomial(GF2Polynomial polynomial, GF2nField B1) {
			this.size_Renamed = B1.Degree + 1;
			this.coeff        = new GF2nElement[this.size_Renamed];
			int i;

			if(B1 is GF2nONBField) {
				for(i = 0; i < this.size_Renamed; i++) {
					if(polynomial.testBit(i)) {
						this.coeff[i] = GF2nONBElement.ONE((GF2nONBField) B1);
					} else {
						this.coeff[i] = GF2nONBElement.ZERO((GF2nONBField) B1);
					}
				}
			} else if(B1 is GF2nPolynomialField) {
				for(i = 0; i < this.size_Renamed; i++) {
					if(polynomial.testBit(i)) {
						this.coeff[i] = GF2nPolynomialElement.ONE((GF2nPolynomialField) B1);
					} else {
						this.coeff[i] = GF2nPolynomialElement.ZERO((GF2nPolynomialField) B1);
					}
				}
			} else {
				throw new ArgumentException("PolynomialGF2n(Bitstring, GF2nField): B1 must be " + "an instance of GF2nONBField or GF2nPolynomialField!");
			}
		}

		/// <summary>
		///     Returns the degree of this PolynomialGF2n.
		/// </summary>
		/// <returns> the degree of this PolynomialGF2n. </returns>
		public int Degree {
			get {
				int i;

				for(i = this.size_Renamed - 1; i >= 0; i--) {
					if(!this.coeff[i].Zero) {
						return i;
					}
				}

				return -1;
			}
		}

		/// <summary>
		///     Returns true if all coefficients equal zero.
		/// </summary>
		/// <returns> true if all coefficients equal zero. </returns>
		public bool Zero {
			get {
				int i;

				for(i = 0; i < this.size_Renamed; i++) {
					if(this.coeff[i] != null) {
						if(!this.coeff[i].Zero) {
							return false;
						}
					}
				}

				return true;
			}
		}

		public void assignZeroToElements() {
			int i;

			for(i = 0; i < this.size_Renamed; i++) {
				this.coeff[i].assignZero();
			}
		}

		/// <summary>
		///     Returns the size (=maximum degree + 1) of this PolynomialGF2n. This is
		///     not the degree, use getDegree instead.
		/// </summary>
		/// <returns> the size (=maximum degree + 1) of this PolynomialGF2n. </returns>
		public int size() {
			return this.size_Renamed;
		}

		/// <summary>
		///     Enlarges the size of this PolynomialGF2n to <i>k</i> + 1.
		/// </summary>
		/// <param name="k"> the new maximum degree </param>
		public void enlarge(int k) {
			if(k <= this.size_Renamed) {
				return;
			}

			int           i;
			GF2nElement[] res = new GF2nElement[k];
			Array.Copy(this.coeff, 0, res, 0, this.size_Renamed);
			GF2nField f = this.coeff[0].Field;

			if(this.coeff[0] is GF2nPolynomialElement) {
				for(i = this.size_Renamed; i < k; i++) {
					res[i] = GF2nPolynomialElement.ZERO((GF2nPolynomialField) f);
				}
			} else if(this.coeff[0] is GF2nONBElement) {
				for(i = this.size_Renamed; i < k; i++) {
					res[i] = GF2nONBElement.ZERO((GF2nONBField) f);
				}
			}

			this.size_Renamed = k;
			this.coeff        = res;
		}

		public void shrink() {
			int i = this.size_Renamed - 1;

			while(this.coeff[i].Zero && (i > 0)) {
				i--;
			}

			i++;

			if(i < this.size_Renamed) {
				GF2nElement[] res = new GF2nElement[i];
				Array.Copy(this.coeff, 0, res, 0, i);
				this.coeff        = res;
				this.size_Renamed = i;
			}
		}

		/// <summary>
		///     Sets the coefficient at <i>index</i> to <i>elem</i>.
		/// </summary>
		/// <param name="index"> the index </param>
		/// <param name="elem">  the GF2nElement to store as coefficient <i>index</i> </param>
		public void set(int index, GF2nElement elem) {
			if(!(elem is GF2nPolynomialElement) && !(elem is GF2nONBElement)) {
				throw new ArgumentException("PolynomialGF2n.set f must be an " + "instance of either GF2nPolynomialElement or GF2nONBElement!");
			}

			this.coeff[index] = (GF2nElement) elem.clone();
		}

		/// <summary>
		///     Returns the coefficient at <i>index</i>.
		/// </summary>
		/// <param name="index"> the index </param>
		/// <returns> the GF2nElement stored as coefficient <i>index</i> </returns>
		public GF2nElement at(int index) {
			return this.coeff[index];
		}

		public override sealed bool Equals(object other) {
			if((other == null) || !(other is GF2nPolynomial)) {
				return false;
			}

			GF2nPolynomial otherPol = (GF2nPolynomial) other;

			if(this.Degree != otherPol.Degree) {
				return false;
			}

			int i;

			for(i = 0; i < this.size_Renamed; i++) {
				if(!this.coeff[i].Equals(otherPol.coeff[i])) {
					return false;
				}
			}

			return true;
		}

		/// <returns> the hash code of this polynomial </returns>
		public override int GetHashCode() {
			return this.Degree + this.coeff.GetHashCode();
		}

		/// <summary>
		///     Adds the PolynomialGF2n <tt>b</tt> to <tt>this</tt> and returns the
		///     result in a new <tt>PolynomialGF2n</tt>.
		/// </summary>
		/// <param name="b">
		///     -
		///     the <tt>PolynomialGF2n</tt> to add
		/// </param>
		/// <returns>
		///     <tt>this + b</tt>
		/// </returns>
		public GF2nPolynomial add(GF2nPolynomial b) {
			GF2nPolynomial result;

			if(this.size() >= b.size()) {
				result = new GF2nPolynomial(this.size());
				int i;

				for(i = 0; i < b.size(); i++) {
					result.coeff[i] = (GF2nElement) this.coeff[i].add(b.coeff[i]);
				}

				for(; i < this.size(); i++) {
					result.coeff[i] = this.coeff[i];
				}
			} else {
				result = new GF2nPolynomial(b.size());
				int i;

				for(i = 0; i < this.size(); i++) {
					result.coeff[i] = (GF2nElement) this.coeff[i].add(b.coeff[i]);
				}

				for(; i < b.size(); i++) {
					result.coeff[i] = b.coeff[i];
				}
			}

			return result;
		}

		/// <summary>
		///     Multiplies the scalar <i>s</i> to each coefficient of this
		///     PolynomialGF2n and returns the result in a new PolynomialGF2n.
		/// </summary>
		/// <param name="s"> the scalar to multiply </param>
		/// <returns> <i>this</i> x <i>s</i> </returns>
		public GF2nPolynomial scalarMultiply(GF2nElement s) {
			GF2nPolynomial result = new GF2nPolynomial(this.size());
			int            i;

			for(i = 0; i < this.size(); i++) {
				result.coeff[i] = (GF2nElement) this.coeff[i].multiply(s); // result[i]

				// =
				// a[i]*s
			}

			return result;
		}

		/// <summary>
		///     Multiplies <i>this</i> by <i>b</i> and returns the result in a new
		///     PolynomialGF2n.
		/// </summary>
		/// <param name="b"> the PolynomialGF2n to multiply </param>
		/// <returns> <i>this</i> * <i>b</i> </returns>
		public GF2nPolynomial multiply(GF2nPolynomial b) {
			int i, j;
			int aDegree = this.size();
			int bDegree = b.size();

			if(aDegree != bDegree) {
				throw new ArgumentException("PolynomialGF2n.multiply: this and b must " + "have the same size!");
			}

			GF2nPolynomial result = new GF2nPolynomial((aDegree << 1) - 1);

			for(i = 0; i < this.size(); i++) {
				for(j = 0; j < b.size(); j++) {
					if(result.coeff[i + j] == null) {
						result.coeff[i + j] = (GF2nElement) this.coeff[i].multiply(b.coeff[j]);
					} else {
						result.coeff[i + j] = (GF2nElement) result.coeff[i + j].add(this.coeff[i].multiply(b.coeff[j]));
					}
				}
			}

			return result;
		}

		/// <summary>
		///     Multiplies <i>this</i> by <i>b</i>, reduces the result by <i>g</i> and
		///     returns it in a new PolynomialGF2n.
		/// </summary>
		/// <param name="b"> the PolynomialGF2n to multiply </param>
		/// <param name="g"> the modul </param>
		/// <returns> <i>this</i> * <i>b</i> mod <i>g</i> </returns>
		public GF2nPolynomial multiplyAndReduce(GF2nPolynomial b, GF2nPolynomial g) {
			return this.multiply(b).reduce(g);
		}

		/// <summary>
		///     Reduces <i>this</i> by <i>g</i> and returns the result in a new
		///     PolynomialGF2n.
		/// </summary>
		/// <param name="g">
		///     -
		///     the modulus
		/// </param>
		/// <returns> <i>this</i> % <i>g</i> </returns>
		public GF2nPolynomial reduce(GF2nPolynomial g) {
			return this.remainder(g); // return this % g
		}

		/// <summary>
		///     Shifts left <i>this</i> by <i>amount</i> and stores the result in
		///     <i>this</i> PolynomialGF2n.
		/// </summary>
		/// <param name="amount"> the amount to shift the coefficients </param>
		public void shiftThisLeft(int amount) {
			if(amount > 0) {
				int       i;
				int       oldSize = this.size_Renamed;
				GF2nField f       = this.coeff[0].Field;
				this.enlarge(this.size_Renamed + amount);

				for(i = oldSize - 1; i >= 0; i--) {
					this.coeff[i + amount] = this.coeff[i];
				}

				if(this.coeff[0] is GF2nPolynomialElement) {
					for(i = amount - 1; i >= 0; i--) {
						this.coeff[i] = GF2nPolynomialElement.ZERO((GF2nPolynomialField) f);
					}
				} else if(this.coeff[0] is GF2nONBElement) {
					for(i = amount - 1; i >= 0; i--) {
						this.coeff[i] = GF2nONBElement.ZERO((GF2nONBField) f);
					}
				}
			}
		}

		public GF2nPolynomial shiftLeft(int amount) {
			if(amount <= 0) {
				return new GF2nPolynomial(this);
			}

			GF2nPolynomial result = new GF2nPolynomial(this.size_Renamed + amount, this.coeff[0]);
			result.assignZeroToElements();

			for(int i = 0; i < this.size_Renamed; i++) {
				result.coeff[i + amount] = this.coeff[i];
			}

			return result;
		}

		/// <summary>
		///     Divides <i>this</i> by <i>b</i> and stores the result in a new
		///     PolynomialGF2n[2], quotient in result[0] and remainder in result[1].
		/// </summary>
		/// <param name="b"> the divisor </param>
		/// <returns> the quotient and remainder of <i>this</i> / <i>b</i> </returns>
		public GF2nPolynomial[] divide(GF2nPolynomial b) {
			GF2nPolynomial[] result = new GF2nPolynomial[2];
			GF2nPolynomial   a      = new GF2nPolynomial(this);
			a.shrink();
			GF2nPolynomial shift;
			GF2nElement    factor;
			int            bDegree = b.Degree;
			GF2nElement    inv     = (GF2nElement) b.coeff[bDegree].invert();

			if(a.Degree < bDegree) {
				result[0] = new GF2nPolynomial(this);
				result[0].assignZeroToElements();
				result[0].shrink();
				result[1] = new GF2nPolynomial(this);
				result[1].shrink();

				return result;
			}

			result[0] = new GF2nPolynomial(this);
			result[0].assignZeroToElements();
			int i = a.Degree - bDegree;

			while(i >= 0) {
				factor = (GF2nElement) a.coeff[a.Degree].multiply(inv);
				shift  = b.scalarMultiply(factor);
				shift.shiftThisLeft(i);
				a = a.add(shift);
				a.shrink();
				result[0].coeff[i] = (GF2nElement) factor.clone();
				i                  = a.Degree - bDegree;
			}

			result[1] = a;
			result[0].shrink();

			return result;
		}

		/// <summary>
		///     Divides <i>this</i> by <i>b</i> and stores the remainder in a new
		///     PolynomialGF2n.
		/// </summary>
		/// <param name="b"> the divisor </param>
		/// <returns> the remainder <i>this</i> % <i>b</i> </returns>
		public GF2nPolynomial remainder(GF2nPolynomial b) {
			GF2nPolynomial[] result = new GF2nPolynomial[2];
			result = this.divide(b);

			return result[1];
		}

		/// <summary>
		///     Divides <i>this</i> by <i>b</i> and stores the quotient in a new
		///     PolynomialGF2n.
		/// </summary>
		/// <param name="b"> the divisor </param>
		/// <returns> the quotient <i>this</i> / <i>b</i> </returns>
		public GF2nPolynomial quotient(GF2nPolynomial b) {
			GF2nPolynomial[] result = new GF2nPolynomial[2];
			result = this.divide(b);

			return result[0];
		}

		/// <summary>
		///     Computes the greatest common divisor of <i>this</i> and <i>g</i> and
		///     returns the result in a new PolynomialGF2n.
		/// </summary>
		/// <param name="g">
		///     -
		///     a GF2nPolynomial
		/// </param>
		/// <returns> gcd(<i>this</i>, <i>g</i>) </returns>
		public GF2nPolynomial gcd(GF2nPolynomial g) {
			GF2nPolynomial a = new GF2nPolynomial(this);
			GF2nPolynomial b = new GF2nPolynomial(g);
			a.shrink();
			b.shrink();
			GF2nPolynomial c;
			GF2nPolynomial result;
			GF2nElement    alpha;

			while(!b.Zero) {
				c = a.remainder(b);
				a = b;
				b = c;
			}

			alpha  = a.coeff[a.Degree];
			result = a.scalarMultiply((GF2nElement) alpha.invert());

			return result;
		}
	}

}
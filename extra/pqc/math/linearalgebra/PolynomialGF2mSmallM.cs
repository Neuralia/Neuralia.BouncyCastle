using System;
using Neuralia.Blockchains.Tools.Data;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class describes operations with polynomials from the ring R =
	///     GF(2^m)[X], where 2 &lt;= m &lt;=31.
	/// </summary>
	/// <seealso cref= GF2mField
	/// </seealso>
	/// <seealso cref= PolynomialRingGF2m
	/// </seealso>
	public class PolynomialGF2mSmallM {

		/*
		  * some types of polynomials
		  */

		/// <summary>
		///     Constant used for polynomial construction (see constructor
		///     <seealso cref="#PolynomialGF2mSmallM(GF2mField, int, char, SecureRandom)" />).
		/// </summary>
		public const char RANDOM_IRREDUCIBLE_POLYNOMIAL = 'I';

		/// <summary>
		///     For the polynomial representation the map f: R->Z*,
		///     <tt>poly(X) -> [coef_0, coef_1, ...]</tt> is used, where
		///     <tt>coef_i</tt> is the <tt>i</tt>th coefficient of the polynomial
		///     represented as int (see <seealso cref="GF2mField" />). The polynomials are stored
		///     as int arrays.
		/// </summary>
		private int[] coefficients;

		/// <summary>
		///     the degree of this polynomial
		/// </summary>
		private int degree;

		/// <summary>
		///     the finite field GF(2^m)
		/// </summary>
		private readonly GF2mField field;

		/// <summary>
		///     Construct the zero polynomial over the finite field GF(2^m).
		/// </summary>
		/// <param name="field"> the finite field GF(2^m) </param>
		public PolynomialGF2mSmallM(GF2mField field) {
			this.field        = field;
			this.degree       = -1;
			this.coefficients = new int[1];
		}

		/// <summary>
		///     Construct a polynomial over the finite field GF(2^m).
		/// </summary>
		/// <param name="field">            the finite field GF(2^m) </param>
		/// <param name="deg">              degree of polynomial </param>
		/// <param name="typeOfPolynomial"> type of polynomial </param>
		/// <param name="sr">               PRNG </param>
		public PolynomialGF2mSmallM(GF2mField field, int deg, char typeOfPolynomial, SecureRandom sr) {
			this.field = field;

			switch(typeOfPolynomial) {
				case RANDOM_IRREDUCIBLE_POLYNOMIAL:
					this.coefficients = this.createRandomIrreduciblePolynomial(deg, sr);

					break;
				default:

					throw new ArgumentException(" Error: type " + typeOfPolynomial + " is not defined for GF2smallmPolynomial");
			}

			this.computeDegree();
		}

		/// <summary>
		///     Construct a monomial of the given degree over the finite field GF(2^m).
		/// </summary>
		/// <param name="field">  the finite field GF(2^m) </param>
		/// <param name="degree"> the degree of the monomial </param>
		public PolynomialGF2mSmallM(GF2mField field, int degree) {
			this.field                = field;
			this.degree               = degree;
			this.coefficients         = new int[degree + 1];
			this.coefficients[degree] = 1;
		}

		/// <summary>
		///     Construct the polynomial over the given finite field GF(2^m) from the
		///     given coefficient vector.
		/// </summary>
		/// <param name="field">  finite field GF2m </param>
		/// <param name="coeffs"> the coefficient vector </param>
		public PolynomialGF2mSmallM(GF2mField field, int[] coeffs) {
			this.field        = field;
			this.coefficients = normalForm(coeffs);
			this.computeDegree();
		}

		/// <summary>
		///     Create a polynomial over the finite field GF(2^m).
		/// </summary>
		/// <param name="field"> the finite field GF(2^m) </param>
		/// <param name="enc">   ArrayWrapper polynomial in byte array form </param>
		public PolynomialGF2mSmallM(GF2mField field, SafeArrayHandle enc) {
			this.field = field;

			// decodes polynomial
			int d     = 8;
			int count = 1;

			while(field.Degree > d) {
				count++;
				d += 8;
			}

			if((enc.Length % count) != 0) {
				throw new ArgumentException(" Error: byte array is not encoded polynomial over given finite field GF2m");
			}

			this.coefficients = new int[enc.Length / count];
			count             = 0;

			for(int i = 0; i < this.coefficients.Length; i++) {
				for(int j = 0; j < d; j += 8) {
					this.coefficients[i] ^= (enc[count++] & 0x000000ff) << j;
				}

				if(!this.field.isElementOfThisField(this.coefficients[i])) {
					throw new ArgumentException(" Error: byte array is not encoded polynomial over given finite field GF2m");
				}
			}

			// if HC = 0 for non-zero polynomial, returns error
			if((this.coefficients.Length != 1) && (this.coefficients[this.coefficients.Length - 1] == 0)) {
				throw new ArgumentException(" Error: byte array is not encoded polynomial over given finite field GF2m");
			}

			this.computeDegree();
		}

		/// <summary>
		///     Copy constructor.
		/// </summary>
		/// <param name="other"> another <seealso cref="PolynomialGF2mSmallM" /> </param>
		public PolynomialGF2mSmallM(PolynomialGF2mSmallM other) {
			// field needs not to be cloned since it is immutable
			this.field        = other.field;
			this.degree       = other.degree;
			this.coefficients = IntUtils.clone(other.coefficients);
		}

		/// <summary>
		///     Create a polynomial over the finite field GF(2^m) out of the given
		///     coefficient vector. The finite field is also obtained from the
		///     <seealso cref="GF2mVector" />.
		/// </summary>
		/// <param name="vect"> the coefficient vector </param>
		public PolynomialGF2mSmallM(GF2mVector vect) : this(vect.Field, vect.IntArrayForm) {
		}

		/*
		  * ------------------------
		  */

		/// <summary>
		///     Return the degree of this polynomial
		/// </summary>
		/// <returns>
		///     int degree of this polynomial if this is zero polynomial return
		///     -1
		/// </returns>
		public virtual int Degree {
			get {
				int d = this.coefficients.Length - 1;

				if(this.coefficients[d] == 0) {
					return -1;
				}

				return d;
			}
		}

		/// <returns> the head coefficient of this polynomial </returns>
		public virtual int HeadCoefficient {
			get {
				if(this.degree == -1) {
					return 0;
				}

				return this.coefficients[this.degree];
			}
		}

		/// <summary>
		///     Returns encoded polynomial, i.e., this polynomial in byte array form
		/// </summary>
		/// <returns> the encoded polynomial </returns>
		public virtual SafeArrayHandle Encoded {
			get {
				int d     = 8;
				int count = 1;

				while(this.field.Degree > d) {
					count++;
					d += 8;
				}

				SafeArrayHandle res = ByteArray.Create(this.coefficients.Length * count);
				count = 0;

				for(int i = 0; i < this.coefficients.Length; i++) {
					for(int j = 0; j < d; j += 8) {
						res[count++] = (byte) (int) ((uint) this.coefficients[i] >> j);
					}
				}

				return res;
			}
		}

		/// <summary>
		///     Create an irreducible polynomial with the given degree over the field
		///     <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="deg"> polynomial degree </param>
		/// <param name="sr">  source of randomness </param>
		/// <returns> the generated irreducible polynomial </returns>
		private int[] createRandomIrreduciblePolynomial(int deg, SecureRandom sr) {
			int[] resCoeff = new int[deg + 1];
			resCoeff[deg] = 1;
			resCoeff[0]   = this.field.getRandomNonZeroElement(sr);

			for(int i = 1; i < deg; i++) {
				resCoeff[i] = this.field.getRandomElement(sr);
			}

			while(!this.isIrreducible(resCoeff)) {
				int n = RandUtils.nextInt(sr, deg);

				if(n == 0) {
					resCoeff[0] = this.field.getRandomNonZeroElement(sr);
				} else {
					resCoeff[n] = this.field.getRandomElement(sr);
				}
			}

			return resCoeff;
		}

		/// <summary>
		///     Return the head coefficient of a polynomial.
		/// </summary>
		/// <param name="a"> the polynomial </param>
		/// <returns> the head coefficient of <tt>a</tt> </returns>
		private static int headCoefficient(int[] a) {
			int degree = computeDegree(a);

			if(degree == -1) {
				return 0;
			}

			return a[degree];
		}

		/// <summary>
		///     Return the coefficient with the given index.
		/// </summary>
		/// <param name="index"> the index </param>
		/// <returns> the coefficient with the given index </returns>
		public virtual int getCoefficient(int index) {
			if((index < 0) || (index > this.degree)) {
				return 0;
			}

			return this.coefficients[index];
		}

		/// <summary>
		///     Evaluate this polynomial <tt>p</tt> at a value <tt>e</tt> (in
		///     <tt>GF(2^m)</tt>) with the Horner scheme.
		/// </summary>
		/// <param name="e"> the element of the finite field GF(2^m) </param>
		/// <returns>
		///     <tt>this(e)</tt>
		/// </returns>
		public virtual int evaluateAt(int e) {
			int result = this.coefficients[this.degree];

			for(int i = this.degree - 1; i >= 0; i--) {
				result = this.field.mult(result, e) ^ this.coefficients[i];
			}

			return result;
		}

		/// <summary>
		///     Compute the sum of this polynomial and the given polynomial.
		/// </summary>
		/// <param name="addend"> the addend </param>
		/// <returns> <tt>this + a</tt> (newly created) </returns>
		public virtual PolynomialGF2mSmallM add(PolynomialGF2mSmallM addend) {
			int[] resultCoeff = this.add(this.coefficients, addend.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Add the given polynomial to this polynomial (overwrite this).
		/// </summary>
		/// <param name="addend"> the addend </param>
		public virtual void addToThis(PolynomialGF2mSmallM addend) {
			this.coefficients = this.add(this.coefficients, addend.coefficients);
			this.computeDegree();
		}

		/// <summary>
		///     Compute the sum of two polynomials a and b over the finite field
		///     <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="b"> the second polynomial </param>
		/// <returns> a + b </returns>
		private int[] add(int[] a, int[] b) {
			int[] result, addend;

			if(a.Length < b.Length) {
				result = new int[b.Length];
				Array.Copy(b, 0, result, 0, b.Length);
				addend = a;
			} else {
				result = new int[a.Length];
				Array.Copy(a, 0, result, 0, a.Length);
				addend = b;
			}

			for(int i = addend.Length - 1; i >= 0; i--) {
				result[i] = this.field.add(result[i], addend[i]);
			}

			return result;
		}

		/// <summary>
		///     Compute the sum of this polynomial and the monomial of the given degree.
		/// </summary>
		/// <param name="degree"> the degree of the monomial </param>
		/// <returns>
		///     <tt>this + X^k</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM addMonomial(int degree) {
			int[] monomial = new int[degree + 1];
			monomial[degree] = 1;
			int[] resultCoeff = this.add(this.coefficients, monomial);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the product of this polynomial with an element from GF(2^m).
		/// </summary>
		/// <param name="element"> an element of the finite field GF(2^m) </param>
		/// <returns> <tt>this * element</tt> (newly created) </returns>
		/// <exception cref="ArithmeticException">
		///     if <tt>element</tt> is not an element of the finite
		///     field this polynomial is defined over.
		/// </exception>
		public virtual PolynomialGF2mSmallM multWithElement(int element) {
			if(!this.field.isElementOfThisField(element)) {
				throw new ArithmeticException("Not an element of the finite field this polynomial is defined over.");
			}

			int[] resultCoeff = this.multWithElement(this.coefficients, element);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Multiply this polynomial with an element from GF(2^m).
		/// </summary>
		/// <param name="element"> an element of the finite field GF(2^m) </param>
		/// <exception cref="ArithmeticException">
		///     if <tt>element</tt> is not an element of the finite
		///     field this polynomial is defined over.
		/// </exception>
		public virtual void multThisWithElement(int element) {
			if(!this.field.isElementOfThisField(element)) {
				throw new ArithmeticException("Not an element of the finite field this polynomial is defined over.");
			}

			this.coefficients = this.multWithElement(this.coefficients, element);
			this.computeDegree();
		}

		/// <summary>
		///     Compute the product of a polynomial a with an element from the finite
		///     field <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="a">       the polynomial </param>
		/// <param name="element"> an element of the finite field GF(2^m) </param>
		/// <returns>
		///     <tt>a * element</tt>
		/// </returns>
		private int[] multWithElement(int[] a, int element) {
			int degree = computeDegree(a);

			if((degree == -1) || (element == 0)) {
				return new int[1];
			}

			if(element == 1) {
				return IntUtils.clone(a);
			}

			int[] result = new int[degree + 1];

			for(int i = degree; i >= 0; i--) {
				result[i] = this.field.mult(a[i], element);
			}

			return result;
		}

		/// <summary>
		///     Compute the product of this polynomial with a monomial X^k.
		/// </summary>
		/// <param name="k"> the degree of the monomial </param>
		/// <returns>
		///     <tt>this * X^k</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM multWithMonomial(int k) {
			int[] resultCoeff = multWithMonomial(this.coefficients, k);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the product of a polynomial with a monomial X^k.
		/// </summary>
		/// <param name="a"> the polynomial </param>
		/// <param name="k"> the degree of the monomial </param>
		/// <returns>
		///     <tt>a * X^k</tt>
		/// </returns>
		private static int[] multWithMonomial(int[] a, int k) {
			int d = computeDegree(a);

			if(d == -1) {
				return new int[1];
			}

			int[] result = new int[d + k + 1];
			Array.Copy(a, 0, result, k, d + 1);

			return result;
		}

		/// <summary>
		///     Divide this polynomial by the given polynomial.
		/// </summary>
		/// <param name="f"> a polynomial </param>
		/// <returns>
		///     polynomial pair = {q,r} where this = q*f+r and deg(r) &lt;
		///     deg(f);
		/// </returns>
		public virtual PolynomialGF2mSmallM[] div(PolynomialGF2mSmallM f) {
			int[][] resultCoeffs = this.div(this.coefficients, f.coefficients);

			return new[] {new PolynomialGF2mSmallM(this.field, resultCoeffs[0]), new PolynomialGF2mSmallM(this.field, resultCoeffs[1])};
		}

		/// <summary>
		///     Compute the result of the division of two polynomials over the field
		///     <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="f"> the second polynomial </param>
		/// <returns> int[][] {q,r}, where a = q*f+r and deg(r) &lt; deg(f); </returns>
		private int[][] div(int[] a, int[] f) {
			int df = computeDegree(f);
			int da = computeDegree(a) + 1;

			if(df == -1) {
				throw new ArithmeticException("Division by zero.");
			}

			int[][] result = new int[2][];
			result[0] = new int[1];
			result[1] = new int[da];
			int hc = headCoefficient(f);
			hc           = this.field.inverse(hc);
			result[0][0] = 0;
			Array.Copy(a, 0, result[1], 0, result[1].Length);

			while(df <= computeDegree(result[1])) {
				int[] q;
				int[] coeff = new int[1];
				coeff[0] = this.field.mult(headCoefficient(result[1]), hc);
				q        = this.multWithElement(f, coeff[0]);
				int n = computeDegree(result[1]) - df;
				q         = multWithMonomial(q, n);
				coeff     = multWithMonomial(coeff, n);
				result[0] = this.add(coeff, result[0]);
				result[1] = this.add(q, result[1]);
			}

			return result;
		}

		/// <summary>
		///     Return the greatest common divisor of this and a polynomial <i>f</i>
		/// </summary>
		/// <param name="f"> polynomial </param>
		/// <returns> GCD(this, f) </returns>
		public virtual PolynomialGF2mSmallM gcd(PolynomialGF2mSmallM f) {
			int[] resultCoeff = this.gcd(this.coefficients, f.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Return the greatest common divisor of two polynomials over the field
		///     <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="f"> the first polynomial </param>
		/// <param name="g"> the second polynomial </param>
		/// <returns>
		///     <tt>gcd(f, g)</tt>
		/// </returns>
		private int[] gcd(int[] f, int[] g) {
			int[] a = f;
			int[] b = g;

			if(computeDegree(a) == -1) {
				return b;
			}

			while(computeDegree(b) != -1) {
				int[] c = this.mod(a, b);
				a = new int[b.Length];
				Array.Copy(b, 0, a, 0, a.Length);
				b = new int[c.Length];
				Array.Copy(c, 0, b, 0, b.Length);
			}

			int coeff = this.field.inverse(headCoefficient(a));

			return this.multWithElement(a, coeff);
		}

		/// <summary>
		///     Compute the product of this polynomial and the given factor using a
		///     Karatzuba like scheme.
		/// </summary>
		/// <param name="factor"> the polynomial </param>
		/// <returns>
		///     <tt>this * factor</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM multiply(PolynomialGF2mSmallM factor) {
			int[] resultCoeff = this.multiply(this.coefficients, factor.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the product of two polynomials over the field <tt>GF(2^m)</tt>
		///     using a Karatzuba like multiplication.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="b"> the second polynomial </param>
		/// <returns> a * b </returns>
		private int[] multiply(int[] a, int[] b) {
			int[] mult1, mult2;

			if(computeDegree(a) < computeDegree(b)) {
				mult1 = b;
				mult2 = a;
			} else {
				mult1 = a;
				mult2 = b;
			}

			mult1 = normalForm(mult1);
			mult2 = normalForm(mult2);

			if(mult2.Length == 1) {
				return this.multWithElement(mult1, mult2[0]);
			}

			int   d1     = mult1.Length;
			int   d2     = mult2.Length;
			int[] result = new int[(d1 + d2) - 1];

			if(d2 != d1) {
				int[] res1 = new int[d2];
				int[] res2 = new int[d1 - d2];
				Array.Copy(mult1, 0, res1, 0, res1.Length);
				Array.Copy(mult1, d2, res2, 0, res2.Length);
				res1   = this.multiply(res1, mult2);
				res2   = this.multiply(res2, mult2);
				res2   = multWithMonomial(res2, d2);
				result = this.add(res1, res2);
			} else {
				d2 = (int) ((uint) (d1 + 1) >> 1);
				int   d               = d1 - d2;
				int[] firstPartMult1  = new int[d2];
				int[] firstPartMult2  = new int[d2];
				int[] secondPartMult1 = new int[d];
				int[] secondPartMult2 = new int[d];
				Array.Copy(mult1, 0, firstPartMult1, 0, firstPartMult1.Length);
				Array.Copy(mult1, d2, secondPartMult1, 0, secondPartMult1.Length);
				Array.Copy(mult2, 0, firstPartMult2, 0, firstPartMult2.Length);
				Array.Copy(mult2, d2, secondPartMult2, 0, secondPartMult2.Length);
				int[] helpPoly1 = this.add(firstPartMult1, secondPartMult1);
				int[] helpPoly2 = this.add(firstPartMult2, secondPartMult2);
				int[] res1      = this.multiply(firstPartMult1, firstPartMult2);
				int[] res2      = this.multiply(helpPoly1, helpPoly2);
				int[] res3      = this.multiply(secondPartMult1, secondPartMult2);
				res2   = this.add(res2, res1);
				res2   = this.add(res2, res3);
				res3   = multWithMonomial(res3, d2);
				result = this.add(res2, res3);
				result = multWithMonomial(result, d2);
				result = this.add(result, res1);
			}

			return result;
		}

		/*
		  * ---------------- PART II ----------------
		  *
		  */

		/// <summary>
		///     Check a polynomial for irreducibility over the field <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="a"> the polynomial to check </param>
		/// <returns> true if a is irreducible, false otherwise </returns>
		private bool isIrreducible(int[] a) {
			if(a[0] == 0) {
				return false;
			}

			int   d = computeDegree(a) >> 1;
			int[] u = {0, 1};

			int[] Y           = {0, 1};
			int   fieldDegree = this.field.Degree;

			for(int i = 0; i < d; i++) {
				for(int j = fieldDegree - 1; j >= 0; j--) {
					u = this.modMultiply(u, u, a);
				}

				u = normalForm(u);
				int[] g = this.gcd(this.add(u, Y), a);

				if(computeDegree(g) != 0) {
					return false;
				}
			}

			return true;
		}

		/// <summary>
		///     Reduce this polynomial modulo another polynomial.
		/// </summary>
		/// <param name="f"> the reduction polynomial </param>
		/// <returns>
		///     <tt>this mod f</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM mod(PolynomialGF2mSmallM f) {
			int[] resultCoeff = this.mod(this.coefficients, f.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Reduce a polynomial modulo another polynomial.
		/// </summary>
		/// <param name="a"> the polynomial </param>
		/// <param name="f"> the reduction polynomial </param>
		/// <returns>
		///     <tt>a mod f</tt>
		/// </returns>
		private int[] mod(int[] a, int[] f) {
			int df = computeDegree(f);

			if(df == -1) {
				throw new ArithmeticException("Division by zero");
			}

			int[] result = new int[a.Length];
			int   hc     = headCoefficient(f);
			hc = this.field.inverse(hc);
			Array.Copy(a, 0, result, 0, result.Length);

			while(df <= computeDegree(result)) {
				int[] q;
				int   coeff = this.field.mult(headCoefficient(result), hc);
				q      = multWithMonomial(f, computeDegree(result) - df);
				q      = this.multWithElement(q, coeff);
				result = this.add(q, result);
			}

			return result;
		}

		/// <summary>
		///     Compute the product of this polynomial and another polynomial modulo a
		///     third polynomial.
		/// </summary>
		/// <param name="a"> another polynomial </param>
		/// <param name="b"> the reduction polynomial </param>
		/// <returns>
		///     <tt>this * a mod b</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM modMultiply(PolynomialGF2mSmallM a, PolynomialGF2mSmallM b) {
			int[] resultCoeff = this.modMultiply(this.coefficients, a.coefficients, b.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Square this polynomial using a squaring matrix.
		/// </summary>
		/// <param name="matrix"> the squaring matrix </param>
		/// <returns>
		///     <tt>this^2</tt> modulo the reduction polynomial implicitly
		///     given via the squaring matrix
		/// </returns>
		public virtual PolynomialGF2mSmallM modSquareMatrix(PolynomialGF2mSmallM[] matrix) {

			int length = matrix.Length;

			int[] resultCoeff = new int[length];
			int[] thisSquare  = new int[length];

			// square each entry of this polynomial
			for(int i = 0; i < this.coefficients.Length; i++) {
				thisSquare[i] = this.field.mult(this.coefficients[i], this.coefficients[i]);
			}

			// do matrix-vector multiplication
			for(int i = 0; i < length; i++) {
				// compute scalar product of i-th row and coefficient vector
				for(int j = 0; j < length; j++) {
					if(i >= matrix[j].coefficients.Length) {
						continue;
					}

					int scalarTerm = this.field.mult(matrix[j].coefficients[i], thisSquare[j]);
					resultCoeff[i] = this.field.add(resultCoeff[i], scalarTerm);
				}
			}

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the product of two polynomials modulo a third polynomial over the
		///     finite field <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="b"> the second polynomial </param>
		/// <param name="g"> the reduction polynomial </param>
		/// <returns>
		///     <tt>a * b mod g</tt>
		/// </returns>
		private int[] modMultiply(int[] a, int[] b, int[] g) {
			return this.mod(this.multiply(a, b), g);
		}

		/// <summary>
		///     Compute the square root of this polynomial modulo the given polynomial.
		/// </summary>
		/// <param name="a"> the reduction polynomial </param>
		/// <returns>
		///     <tt>this^(1/2) mod a</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM modSquareRoot(PolynomialGF2mSmallM a) {
			int[] resultCoeff = IntUtils.clone(this.coefficients);
			int[] help        = this.modMultiply(resultCoeff, resultCoeff, a.coefficients);

			while(!isEqual(help, this.coefficients)) {
				resultCoeff = normalForm(help);
				help        = this.modMultiply(resultCoeff, resultCoeff, a.coefficients);
			}

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the square root of this polynomial using a square root matrix.
		/// </summary>
		/// <param name="matrix">
		///     the matrix for computing square roots in
		///     <tt>(GF(2^m))^t</tt> the polynomial ring defining the
		///     square root matrix
		/// </param>
		/// <returns>
		///     <tt>this^(1/2)</tt> modulo the reduction polynomial implicitly
		///     given via the square root matrix
		/// </returns>
		public virtual PolynomialGF2mSmallM modSquareRootMatrix(PolynomialGF2mSmallM[] matrix) {

			int length = matrix.Length;

			int[] resultCoeff = new int[length];

			// do matrix multiplication
			for(int i = 0; i < length; i++) {
				// compute scalar product of i-th row and j-th column
				for(int j = 0; j < length; j++) {
					if(i >= matrix[j].coefficients.Length) {
						continue;
					}

					if(j < this.coefficients.Length) {
						int scalarTerm = this.field.mult(matrix[j].coefficients[i], this.coefficients[j]);
						resultCoeff[i] = this.field.add(resultCoeff[i], scalarTerm);
					}
				}
			}

			// compute the square root of each entry of the result coefficients
			for(int i = 0; i < length; i++) {
				resultCoeff[i] = this.field.sqRoot(resultCoeff[i]);
			}

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the result of the division of this polynomial by another
		///     polynomial modulo a third polynomial.
		/// </summary>
		/// <param name="divisor"> the divisor </param>
		/// <param name="modulus"> the reduction polynomial </param>
		/// <returns>
		///     <tt>this * divisor^(-1) mod modulus</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM modDiv(PolynomialGF2mSmallM divisor, PolynomialGF2mSmallM modulus) {
			int[] resultCoeff = this.modDiv(this.coefficients, divisor.coefficients, modulus.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute the result of the division of two polynomials modulo a third
		///     polynomial over the field <tt>GF(2^m)</tt>.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="b"> the second polynomial </param>
		/// <param name="g"> the reduction polynomial </param>
		/// <returns>
		///     <tt>a * b^(-1) mod g</tt>
		/// </returns>
		private int[] modDiv(int[] a, int[] b, int[] g) {
			int[]   r0 = normalForm(g);
			int[]   r1 = this.mod(b, g);
			int[]   s0 = {0};
			int[]   s1 = this.mod(a, g);
			int[]   s2;
			int[][] q;

			while(computeDegree(r1) != -1) {
				q  = this.div(r0, r1);
				r0 = normalForm(r1);
				r1 = normalForm(q[1]);
				s2 = this.add(s0, this.modMultiply(q[0], s1, g));
				s0 = normalForm(s1);
				s1 = normalForm(s2);

			}

			int hc = headCoefficient(r0);
			s0 = this.multWithElement(s0, this.field.inverse(hc));

			return s0;
		}

		/// <summary>
		///     Compute the inverse of this polynomial modulo the given polynomial.
		/// </summary>
		/// <param name="a"> the reduction polynomial </param>
		/// <returns>
		///     <tt>this^(-1) mod a</tt>
		/// </returns>
		public virtual PolynomialGF2mSmallM modInverse(PolynomialGF2mSmallM a) {
			int[] unit        = {1};
			int[] resultCoeff = this.modDiv(unit, this.coefficients, a.coefficients);

			return new PolynomialGF2mSmallM(this.field, resultCoeff);
		}

		/// <summary>
		///     Compute a polynomial pair (a,b) from this polynomial and the given
		///     polynomial g with the property b*this = a mod g and deg(a)&lt;=deg(g)/2.
		/// </summary>
		/// <param name="g"> the reduction polynomial </param>
		/// <returns>
		///     PolynomialGF2mSmallM[] {a,b} with b*this = a mod g and deg(a)&lt;=
		///     deg(g)/2
		/// </returns>
		public virtual PolynomialGF2mSmallM[] modPolynomialToFracton(PolynomialGF2mSmallM g) {
			int   dg = g.degree >> 1;
			int[] a0 = normalForm(g.coefficients);
			int[] a1 = this.mod(this.coefficients, g.coefficients);
			int[] b0 = {0};
			int[] b1 = {1};

			while(computeDegree(a1) > dg) {
				int[][] q = this.div(a0, a1);
				a0 = a1;
				a1 = q[1];
				int[] b2 = this.add(b0, this.modMultiply(q[0], b1, g.coefficients));
				b0 = b1;
				b1 = b2;
			}

			return new[] {new PolynomialGF2mSmallM(this.field, a1), new PolynomialGF2mSmallM(this.field, b1)};
		}

		/// <summary>
		///     checks if given object is equal to this polynomial.
		///     <para>
		///         The method returns false whenever the given object is not polynomial over
		///         GF(2^m).
		///     </para>
		/// </summary>
		/// <param name="other"> object </param>
		/// <returns> true or false </returns>
		public override bool Equals(object other) {

			if((other == null) || !(other is PolynomialGF2mSmallM)) {
				return false;
			}

			PolynomialGF2mSmallM p = (PolynomialGF2mSmallM) other;

			if(this.field.Equals(p.field) && (this.degree == p.degree) && isEqual(this.coefficients, p.coefficients)) {
				return true;
			}

			return false;
		}

		/// <summary>
		///     Compare two polynomials given as int arrays.
		/// </summary>
		/// <param name="a"> the first polynomial </param>
		/// <param name="b"> the second polynomial </param>
		/// <returns>
		///     <tt>true</tt> if <tt>a</tt> and <tt>b</tt> represent the
		///     same polynomials, <tt>false</tt> otherwise
		/// </returns>
		private static bool isEqual(int[] a, int[] b) {
			int da = computeDegree(a);
			int db = computeDegree(b);

			if(da != db) {
				return false;
			}

			for(int i = 0; i <= da; i++) {
				if(a[i] != b[i]) {
					return false;
				}
			}

			return true;
		}

		/// <returns> the hash code of this polynomial </returns>
		public override int GetHashCode() {
			int hash = this.field.GetHashCode();

			for(int j = 0; j < this.coefficients.Length; j++) {
				hash = (hash * 31) + this.coefficients[j];
			}

			return hash;
		}

		/// <summary>
		///     Returns a human readable form of the polynomial.
		/// </summary>
		/// <returns> a human readable form of the polynomial. </returns>
		public override string ToString() {
			string str = " Polynomial over " + this.field + ": \n";

			for(int i = 0; i < this.coefficients.Length; i++) {
				str = str + this.field.elementToStr(this.coefficients[i]) + "Y^" + i + "+";
			}

			str = str + ";";

			return str;
		}

		/// <summary>
		///     Compute the degree of this polynomial. If this is the zero polynomial,
		///     the degree is -1.
		/// </summary>
		private void computeDegree() {
			for(this.degree = this.coefficients.Length - 1; (this.degree >= 0) && (this.coefficients[this.degree] == 0); this.degree--) {
				;
			}
		}

		/// <summary>
		///     Compute the degree of a polynomial.
		/// </summary>
		/// <param name="a"> the polynomial </param>
		/// <returns>
		///     the degree of the polynomial <tt>a</tt>. If <tt>a</tt> is
		///     the zero polynomial, return -1.
		/// </returns>
		private static int computeDegree(int[] a) {
			int degree;

			for(degree = a.Length - 1; (degree >= 0) && (a[degree] == 0); degree--) {
				;
			}

			return degree;
		}

		/// <summary>
		///     Strip leading zero coefficients from the given polynomial.
		/// </summary>
		/// <param name="a"> the polynomial </param>
		/// <returns> the reduced polynomial </returns>
		private static int[] normalForm(int[] a) {
			int d = computeDegree(a);

			// if a is the zero polynomial
			if(d == -1) {
				// return new zero polynomial
				return new int[1];
			}

			// if a already is in normal form
			if(a.Length == (d + 1)) {
				// return a clone of a
				return IntUtils.clone(a);
			}

			// else, reduce a
			int[] result = new int[d + 1];
			Array.Copy(a, 0, result, 0, d + 1);

			return result;
		}
	}

}
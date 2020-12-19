using System;
using System.Collections;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements the abstract class <tt>GF2nField</tt> for polynomial
	///     representation. It computes the field polynomial and the squaring matrix.
	///     GF2nField is used by GF2nPolynomialElement which implements the elements of
	///     this field.
	/// </summary>
	/// <seealso cref= GF2nField
	/// </seealso>
	/// <seealso cref= GF2nPolynomialElement
	/// </seealso>
	public class GF2nPolynomialField : GF2nField {

		// field polynomial is a pentanomial
		private bool isPentanomial;

		// field polynomial is a trinomial
		private bool isTrinomial;

		// middle 3 coefficients of the field polynomial in case it is a pentanomial
		private readonly int[] pc = new int[3];

		/// <summary>
		///     Matrix used for fast squaring
		/// </summary>
		internal GF2Polynomial[] squaringMatrix;

		// middle coefficient of the field polynomial in case it is a trinomial
		private int tc;

		/// <summary>
		///     constructs an instance of the finite field with 2<sup>deg</sup>
		///     elements and characteristic 2.
		/// </summary>
		/// <param name="deg"> the extention degree of this field </param>
		/// <param name="random">     source of randomness for generating new polynomials. </param>
		public GF2nPolynomialField(int deg, SecureRandom random) : base(random) {

			if(deg < 3) {
				throw new ArgumentException("k must be at least 3");
			}

			this.mDegree = deg;
			this.computeFieldPolynomial();
			this.computeSquaringMatrix();
			this.fields   = new ArrayList();
			this.matrices = new ArrayList();
		}

		/// <summary>
		///     constructs an instance of the finite field with 2<sup>deg</sup>
		///     elements and characteristic 2.
		/// </summary>
		/// <param name="deg">  the degree of this field </param>
		/// <param name="random">     source of randomness for generating new polynomials. </param>
		/// <param name="file">
		///     true if you want to read the field polynomial from the
		///     file false if you want to use a random fielpolynomial
		///     (this can take very long for huge degrees)
		/// </param>
		public GF2nPolynomialField(int deg, SecureRandom random, bool file) : base(random) {

			if(deg < 3) {
				throw new ArgumentException("k must be at least 3");
			}

			this.mDegree = deg;

			if(file) {
				this.computeFieldPolynomial();
			} else {
				this.computeFieldPolynomial2();
			}

			this.computeSquaringMatrix();
			this.fields   = new ArrayList();
			this.matrices = new ArrayList();
		}

		/// <summary>
		///     Creates a new GF2nField of degree <i>i</i> and uses the given
		///     <i>polynomial</i> as field polynomial. The <i>polynomial</i> is checked
		///     whether it is irreducible. This can take some time if <i>i</i> is huge!
		/// </summary>
		/// <param name="deg">        degree of the GF2nField </param>
		/// <param name="random">     source of randomness for generating new polynomials. </param>
		/// <param name="polynomial"> the field polynomial to use </param>
		public GF2nPolynomialField(int deg, SecureRandom random, GF2Polynomial polynomial) : base(random) {

			if(deg < 3) {
				throw new ArgumentException("degree must be at least 3");
			}

			if(polynomial.Length != (deg + 1)) {
				throw new Exception();
			}

			if(!polynomial.Irreducible) {
				throw new Exception();
			}

			this.mDegree = deg;

			// fieldPolynomial = new Bitstring(polynomial);
			this.fieldPolynomial = polynomial;
			this.computeSquaringMatrix();
			int k = 2; // check if the polynomial is a trinomial or pentanomial

			for(int j = 1; j < (this.fieldPolynomial.Length - 1); j++) {
				if(this.fieldPolynomial.testBit(j)) {
					k++;

					if(k == 3) {
						this.tc = j;
					}

					if(k <= 5) {
						this.pc[k - 3] = j;
					}
				}
			}

			if(k == 3) {
				this.isTrinomial = true;
			}

			if(k == 5) {
				this.isPentanomial = true;
			}

			this.fields   = new ArrayList();
			this.matrices = new ArrayList();
		}

		/// <summary>
		///     Returns true if the field polynomial is a trinomial. The coefficient can
		///     be retrieved using getTc().
		/// </summary>
		/// <returns> true if the field polynomial is a trinomial </returns>
		public virtual bool Trinomial => this.isTrinomial;

		/// <summary>
		///     Returns true if the field polynomial is a pentanomial. The coefficients
		///     can be retrieved using getPc().
		/// </summary>
		/// <returns> true if the field polynomial is a pentanomial </returns>
		public virtual bool Pentanomial => this.isPentanomial;

		/// <summary>
		///     Returns the degree of the middle coefficient of the used field trinomial
		///     (x^n + x^(getTc()) + 1).
		/// </summary>
		/// <returns> the middle coefficient of the used field trinomial </returns>

		public virtual int Tc {
			get {
				if(!this.isTrinomial) {
					throw new Exception();
				}

				return this.tc;
			}
		}

		/// <summary>
		///     Returns the degree of the middle coefficients of the used field
		///     pentanomial (x^n + x^(getPc()[2]) + x^(getPc()[1]) + x^(getPc()[0]) + 1).
		/// </summary>
		/// <returns> the middle coefficients of the used field pentanomial </returns>

		public virtual int[] Pc {
			get {
				if(!this.isPentanomial) {
					throw new Exception();
				}

				int[] result = new int[3];
				Array.Copy(this.pc, 0, result, 0, 3);

				return result;
			}
		}

		/// <summary>
		///     Return row vector i of the squaring matrix.
		/// </summary>
		/// <param name="i"> the index of the row vector to return </param>
		/// <returns> a copy of squaringMatrix[i] </returns>
		/// <seealso cref= GF2nPolynomialElement# squareMatrix
		/// </seealso>
		public virtual GF2Polynomial getSquaringVector(int i) {
			return new GF2Polynomial(this.squaringMatrix[i]);
		}

		/// <summary>
		///     Compute a random root of the given GF2Polynomial.
		/// </summary>
		/// <param name="polynomial"> the polynomial </param>
		/// <returns> a random root of <tt>polynomial</tt> </returns>
		protected internal override GF2nElement getRandomRoot(GF2Polynomial polynomial) {
			// We are in B1!!!
			GF2nPolynomial c;
			GF2nPolynomial ut;
			GF2nElement    u;
			GF2nPolynomial h;
			int            hDegree;

			// 1. Set g(t) <- f(t)
			GF2nPolynomial g       = new GF2nPolynomial(polynomial, this);
			int            gDegree = g.Degree;
			int            i;

			// 2. while deg(g) > 1
			while(gDegree > 1) {
				do {
					// 2.1 choose random u (element of) GF(2^m)
					u  = new GF2nPolynomialElement(this, this.random);
					ut = new GF2nPolynomial(2, GF2nPolynomialElement.ZERO(this));

					// 2.2 Set c(t) <- ut
					ut.set(1, u);
					c = new GF2nPolynomial(ut);

					// 2.3 For i from 1 to m-1 do
					for(i = 1; i <= (this.mDegree - 1); i++) {
						// 2.3.1 c(t) <- (c(t)^2 + ut) mod g(t)
						c = c.multiplyAndReduce(c, g);
						c = c.add(ut);
					}

					// 2.4 set h(t) <- GCD(c(t), g(t))
					h = c.gcd(g);

					// 2.5 if h(t) is constant or deg(g) = deg(h) then go to
					// step 2.1
					hDegree = h.Degree;
					gDegree = g.Degree;
				} while((hDegree == 0) || (hDegree == gDegree));

				// 2.6 If 2deg(h) > deg(g) then set g(t) <- g(t)/h(t) ...
				if((hDegree << 1) > gDegree) {
					g = g.quotient(h);
				} else {
					// ... else g(t) <- h(t)
					g = new GF2nPolynomial(h);
				}

				gDegree = g.Degree;
			}

			// 3. Output g(0)
			return g.at(0);

		}

		/// <summary>
		///     Computes the change-of-basis matrix for basis conversion according to
		///     1363. The result is stored in the lists fields and matrices.
		/// </summary>
		/// <param name="B1"> the GF2nField to convert to </param>
		/// <seealso cref="P1363 A.7.3, p111ff"
		/// </seealso>
		protected internal override void computeCOBMatrix(GF2nField B1) {
			// we are in B0 here!
			if(this.mDegree != B1.mDegree) {
				throw new ArgumentException("GF2nPolynomialField.computeCOBMatrix: B1 has a different " + "degree and thus cannot be coverted to!");
			}

			if(B1 is GF2nONBField) {
				// speedup (calculation is done in PolynomialElements instead of
				// ONB)
				B1.computeCOBMatrix(this);

				return;
			}

			int             i, j;
			GF2nElement[]   gamma;
			GF2nElement     u;
			GF2Polynomial[] COBMatrix = new GF2Polynomial[this.mDegree];

			for(i = 0; i < this.mDegree; i++) {
				COBMatrix[i] = new GF2Polynomial(this.mDegree);
			}

			// find Random Root
			do {
				// u is in representation according to B1
				u = B1.getRandomRoot(this.fieldPolynomial);
			} while(u.Zero);

			// build gamma matrix by multiplying by u
			if(u is GF2nONBElement) {
				gamma                   = new GF2nONBElement[this.mDegree];
				gamma[this.mDegree - 1] = GF2nONBElement.ONE((GF2nONBField) B1);
			} else {
				gamma                   = new GF2nPolynomialElement[this.mDegree];
				gamma[this.mDegree - 1] = GF2nPolynomialElement.ONE((GF2nPolynomialField) B1);
			}

			gamma[this.mDegree - 2] = u;

			for(i = this.mDegree - 3; i >= 0; i--) {
				gamma[i] = (GF2nElement) gamma[i + 1].multiply(u);
			}

			if(B1 is GF2nONBField) {
				// convert horizontal gamma matrix by vertical Bitstrings
				for(i = 0; i < this.mDegree; i++) {
					for(j = 0; j < this.mDegree; j++) {
						// TODO remember: ONB treats its Bits in reverse order !!!
						if(gamma[i].testBit(this.mDegree - j - 1)) {
							COBMatrix[this.mDegree - j - 1].Bit = this.mDegree - i - 1;
						}
					}
				}
			} else {
				// convert horizontal gamma matrix by vertical Bitstrings
				for(i = 0; i < this.mDegree; i++) {
					for(j = 0; j < this.mDegree; j++) {
						if(gamma[i].testBit(j)) {
							COBMatrix[this.mDegree - j - 1].Bit = this.mDegree - i - 1;
						}
					}
				}
			}

			// store field and matrix for further use
			this.fields.Add(B1);
			this.matrices.Add(COBMatrix);

			// store field and inverse matrix for further use in B1
			B1.fields.Add(this);
			B1.matrices.Add(this.invertMatrix(COBMatrix));
		}

		/// <summary>
		///     Computes a new squaring matrix used for fast squaring.
		/// </summary>
		/// <seealso cref= GF2nPolynomialElement# square
		/// </seealso>
		private void computeSquaringMatrix() {
			GF2Polynomial[] d = new GF2Polynomial[this.mDegree - 1];
			int             i, j;
			this.squaringMatrix = new GF2Polynomial[this.mDegree];

			for(i = 0; i < this.squaringMatrix.Length; i++) {
				this.squaringMatrix[i] = new GF2Polynomial(this.mDegree, "ZERO");
			}

			for(i = 0; i < (this.mDegree - 1); i++) {
				d[i] = new GF2Polynomial(1, "ONE").shiftLeft(this.mDegree + i).remainder(this.fieldPolynomial);
			}

			for(i = 1; i <= Math.Abs(this.mDegree >> 1); i++) {
				for(j = 1; j <= this.mDegree; j++) {
					if(d[this.mDegree - (i << 1)].testBit(this.mDegree - j)) {
						this.squaringMatrix[j - 1].Bit = this.mDegree - i;
					}
				}
			}

			for(i = Math.Abs(this.mDegree >> 1) + 1; i <= this.mDegree; i++) {
				this.squaringMatrix[(i << 1) - this.mDegree - 1].Bit = this.mDegree - i;
			}

		}

		/// <summary>
		///     Computes the field polynomial. This can take a long time for big degrees.
		/// </summary>
		protected internal override void computeFieldPolynomial() {
			if(this.testTrinomials()) {
				return;
			}

			if(this.testPentanomials()) {
				return;
			}

			this.testRandom();
		}

		/// <summary>
		///     Computes the field polynomial. This can take a long time for big degrees.
		/// </summary>
		protected internal virtual void computeFieldPolynomial2() {
			if(this.testTrinomials()) {
				return;
			}

			if(this.testPentanomials()) {
				return;
			}

			this.testRandom();
		}

		/// <summary>
		///     Tests all trinomials of degree (n+1) until a irreducible is found and
		///     stores the result in <i>field polynomial</i>. Returns false if no
		///     irreducible trinomial exists in GF(2^n). This can take very long for huge
		///     degrees.
		/// </summary>
		/// <returns> true if an irreducible trinomial is found </returns>
		private bool testTrinomials() {
			int  i, l;
			bool done = false;
			l = 0;

			this.fieldPolynomial     = new GF2Polynomial(this.mDegree + 1);
			this.fieldPolynomial.Bit = 0;
			this.fieldPolynomial.Bit = this.mDegree;

			for(i = 1; (i < this.mDegree) && !done; i++) {
				this.fieldPolynomial.Bit = i;
				done                     = this.fieldPolynomial.Irreducible;
				l++;

				if(done) {
					this.isTrinomial = true;
					this.tc          = i;

					return done;
				}

				this.fieldPolynomial.resetBit(i);
				done = this.fieldPolynomial.Irreducible;
			}

			return done;
		}

		/// <summary>
		///     Tests all pentanomials of degree (n+1) until a irreducible is found and
		///     stores the result in <i>field polynomial</i>. Returns false if no
		///     irreducible pentanomial exists in GF(2^n). This can take very long for
		///     huge degrees.
		/// </summary>
		/// <returns> true if an irreducible pentanomial is found </returns>
		private bool testPentanomials() {
			int  i, j, k, l;
			bool done = false;
			l = 0;

			this.fieldPolynomial     = new GF2Polynomial(this.mDegree + 1);
			this.fieldPolynomial.Bit = 0;
			this.fieldPolynomial.Bit = this.mDegree;

			for(i = 1; (i <= (this.mDegree - 3)) && !done; i++) {
				this.fieldPolynomial.Bit = i;

				for(j = i + 1; (j <= (this.mDegree - 2)) && !done; j++) {
					this.fieldPolynomial.Bit = j;

					for(k = j + 1; (k <= (this.mDegree - 1)) && !done; k++) {
						this.fieldPolynomial.Bit = k;

						if(((this.mDegree & 1) != 0) | ((i & 1) != 0) | ((j & 1) != 0) | ((k & 1) != 0)) {
							done = this.fieldPolynomial.Irreducible;
							l++;

							if(done) {
								this.isPentanomial = true;
								this.pc[0]         = i;
								this.pc[1]         = j;
								this.pc[2]         = k;

								return done;
							}
						}

						this.fieldPolynomial.resetBit(k);
					}

					this.fieldPolynomial.resetBit(j);
				}

				this.fieldPolynomial.resetBit(i);
			}

			return done;
		}

		/// <summary>
		///     Tests random polynomials of degree (n+1) until an irreducible is found
		///     and stores the result in <i>field polynomial</i>. This can take very
		///     long for huge degrees.
		/// </summary>
		/// <returns> true </returns>
		private bool testRandom() {
			int  l;
			bool done = false;

			this.fieldPolynomial = new GF2Polynomial(this.mDegree + 1);
			l                    = 0;

			while(!done) {
				l++;
				this.fieldPolynomial.randomize();
				this.fieldPolynomial.Bit = this.mDegree;
				this.fieldPolynomial.Bit = 0;

				if(this.fieldPolynomial.Irreducible) {
					done = true;

					return done;
				}
			}

			return done;
		}
	}

}
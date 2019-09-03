using System;
using System.Collections;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements the abstract class <tt>GF2nField</tt> for ONB
	///     representation. It computes the fieldpolynomial, multiplication matrix and
	///     one of its roots mONBRoot, (see for example
	///     <a
	///         href= http:// www2.certicom.com/ ecc/ intro.htm>
	///         Certicoms Whitepapers
	///     </a>
	///     ).
	///     GF2nField is used by GF2nONBElement which implements the elements of this
	///     field.
	/// </summary>
	/// <seealso cref= GF2nField
	/// </seealso>
	/// <seealso cref= GF2nONBElement
	/// </seealso>
	public class GF2nONBField : GF2nField {

		// ///////////////////////////////////////////////////////////////////
		// Hashtable for irreducible normal polynomials //
		// ///////////////////////////////////////////////////////////////////

		// i*5 + 0 i*5 + 1 i*5 + 2 i*5 + 3 i*5 + 4
		/*
		 * private static int[][] mNB = {{0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {1, 0, 0},
		 * {1, 0, 0}, // i = 0 {2, 0, 0}, {1, 0, 0}, {1, 0, 0}, {4, 3, 1}, {1, 0,
		 * 0}, // i = 1 {3, 0, 0}, {2, 0, 0}, {3, 0, 0}, {4, 3, 1}, {5, 0, 0}, // i =
		 * 2 {1, 0, 0}, {5, 3, 1}, {3, 0, 0}, {3, 0, 0}, {5, 2, 1}, // i = 3 {3, 0,
		 * 0}, {2, 0, 0}, {1, 0, 0}, {5, 0, 0}, {4, 3, 1}, // i = 4 {3, 0, 0}, {4,
		 * 3, 1}, {5, 2, 1}, {1, 0, 0}, {2, 0, 0}, // i = 5 {1, 0, 0}, {3, 0, 0},
		 * {7, 3, 2}, {10, 0, 0}, {7, 0, 0}, // i = 6 {2, 0, 0}, {9, 0, 0}, {6, 4,
		 * 1}, {6, 5, 1}, {4, 0, 0}, // i = 7 {5, 4, 3}, {3, 0, 0}, {7, 0, 0}, {6,
		 * 4, 3}, {5, 0, 0}, // i = 8 {4, 3, 1}, {1, 0, 0}, {5, 0, 0}, {5, 3, 2},
		 * {9, 0, 0}, // i = 9 {4, 3, 2}, {6, 3, 1}, {3, 0, 0}, {6, 2, 1}, {9, 0,
		 * 0}, // i = 10 {7, 0, 0}, {7, 4, 2}, {4, 0, 0}, {19, 0, 0}, {7, 4, 2}, //
		 * i = 11 {1, 0, 0}, {5, 2, 1}, {29, 0, 0}, {1, 0, 0}, {4, 3, 1}, // i = 12
		 * {18, 0, 0}, {3, 0, 0}, {5, 2, 1}, {9, 0, 0}, {6, 5, 2}, // i = 13 {5, 3,
		 * 1}, {6, 0, 0}, {10, 9, 3}, {25, 0, 0}, {35, 0, 0}, // i = 14 {6, 3, 1},
		 * {21, 0, 0}, {6, 5, 2}, {6, 5, 3}, {9, 0, 0}, // i = 15 {9, 4, 2}, {4, 0,
		 * 0}, {8, 3, 1}, {7, 4, 2}, {5, 0, 0}, // i = 16 {8, 2, 1}, {21, 0, 0},
		 * {13, 0, 0}, {7, 6, 2}, {38, 0, 0}, // i = 17 {27, 0, 0}, {8, 5, 1}, {21,
		 * 0, 0}, {2, 0, 0}, {21, 0, 0}, // i = 18 {11, 0, 0}, {10, 9, 6}, {6, 0,
		 * 0}, {11, 0, 0}, {6, 3, 1}, // i = 19 {15, 0, 0}, {7, 6, 1}, {29, 0, 0},
		 * {9, 0, 0}, {4, 3, 1}, // i = 20 {4, 0, 0}, {15, 0, 0}, {9, 7, 4}, {17, 0,
		 * 0}, {5, 4, 2}, // i = 21 {33, 0, 0}, {10, 0, 0}, {5, 4, 3}, {9, 0, 0},
		 * {5, 3, 2}, // i = 22 {8, 7, 5}, {4, 2, 1}, {5, 2, 1}, {33, 0, 0}, {8, 0,
		 * 0}, // i = 23 {4, 3, 1}, {18, 0, 0}, {6, 2, 1}, {2, 0, 0}, {19, 0, 0}, //
		 * i = 24 {7, 6, 5}, {21, 0, 0}, {1, 0, 0}, {7, 2, 1}, {5, 0, 0}, // i = 25
		 * {3, 0, 0}, {8, 3, 2}, {17, 0, 0}, {9, 8, 2}, {57, 0, 0}, // i = 26 {11,
		 * 0, 0}, {5, 3, 2}, {21, 0, 0}, {8, 7, 1}, {8, 5, 3}, // i = 27 {15, 0, 0},
		 * {10, 4, 1}, {21, 0, 0}, {5, 3, 2}, {7, 4, 2}, // i = 28 {52, 0, 0}, {71,
		 * 0, 0}, {14, 0, 0}, {27, 0, 0}, {10, 9, 7}, // i = 29 {53, 0, 0}, {3, 0,
		 * 0}, {6, 3, 2}, {1, 0, 0}, {15, 0, 0}, // i = 30 {62, 0, 0}, {9, 0, 0},
		 * {6, 5, 2}, {8, 6, 5}, {31, 0, 0}, // i = 31 {5, 3, 2}, {18, 0, 0 }, {27,
		 * 0, 0}, {7, 6, 3}, {10, 8, 7}, // i = 32 {9, 8, 3}, {37, 0, 0}, {6, 0, 0},
		 * {15, 3, 2}, {34, 0, 0}, // i = 33 {11, 0, 0}, {6, 5, 2}, {1, 0, 0}, {8,
		 * 5, 2}, {13, 0, 0}, // i = 34 {6, 0, 0}, {11, 3, 2}, {8, 0, 0}, {31, 0,
		 * 0}, {4, 2, 1}, // i = 35 {3, 0, 0}, {7, 6, 1}, {81, 0, 0}, {56, 0, 0},
		 * {9, 8, 7}, // i = 36 {24, 0, 0}, {11, 0, 0}, {7, 6, 5}, {6, 5, 2}, {6, 5,
		 * 2}, // i = 37 {8, 7, 6}, {9, 0, 0}, {7, 2, 1}, {15, 0, 0}, {87, 0, 0}, //
		 * i = 38 {8, 3, 2}, {3, 0, 0}, {9, 4, 2}, {9, 0, 0}, {34, 0, 0}, // i = 39
		 * {5, 3, 2}, {14, 0, 0}, {55, 0, 0}, {8, 7, 1}, {27, 0, 0}, // i = 40 {9,
		 * 5, 2}, {10, 9, 5}, {43, 0, 0}, {8, 6, 2}, {6, 0, 0}, // i = 41 {7, 0, 0},
		 * {11, 10, 8}, {105, 0, 0}, {6, 5, 2}, {73, 0, 0}}; // i = 42
		 */
		// /////////////////////////////////////////////////////////////////////
		// member variables
		// /////////////////////////////////////////////////////////////////////
		private const int MAXLONG = 64;

		/// <summary>
		///     holds the number of relevant bits in mONBPol[mLength-1].
		/// </summary>
		private readonly int mBit;

		/// <summary>
		///     holds the length of the array-representation of degree mDegree.
		/// </summary>
		private readonly int mLength;

		/// <summary>
		///     holds the multiplication matrix
		/// </summary>
		internal int[][] mMult;

		/// <summary>
		///     holds the type of mONB
		/// </summary>
		private int mType;

		// /////////////////////////////////////////////////////////////////////
		// constructors
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     constructs an instance of the finite field with 2<sup>deg</sup>
		///     elements and characteristic 2.
		/// </summary>
		/// <param name="deg"> -the extention degree of this field </param>
		/// <param name="random"> - a source of randomness for generating polynomials on the field. </param>
		public GF2nONBField(int deg, SecureRandom random) : base(random) {

			if(deg < 3) {
				throw new ArgumentException("k must be at least 3");
			}

			this.mDegree = deg;
			this.mLength = this.mDegree / MAXLONG;
			this.mBit    = this.mDegree & (MAXLONG - 1);

			if(this.mBit == 0) {
				this.mBit = MAXLONG;
			} else {
				this.mLength++;
			}

			this.computeType();

			// only ONB-implementations for type 1 and type 2
			//
			if(this.mType < 3) {

				this.mMult = SquareArrays.ReturnRectangularIntArray(this.mDegree, 2);

				for(int i = 0; i < this.mDegree; i++) {
					this.mMult[i][0] = -1;
					this.mMult[i][1] = -1;
				}

				this.computeMultMatrix();
			} else {
				throw new Exception("\nThe type of this field is " + this.mType);
			}

			this.computeFieldPolynomial();
			this.fields   = new ArrayList();
			this.matrices = new ArrayList();
		}

		// /////////////////////////////////////////////////////////////////////
		// access
		// /////////////////////////////////////////////////////////////////////

		internal virtual int ONBLength => this.mLength;

		internal virtual int ONBBit => this.mBit;

		// /////////////////////////////////////////////////////////////////////
		// arithmetic
		// /////////////////////////////////////////////////////////////////////

		/// <summary>
		///     Computes a random root of the given polynomial.
		/// </summary>
		/// <param name="polynomial"> a polynomial </param>
		/// <returns> a random root of the polynomial </returns>
		/// <seealso cref="P1363 A.5.6, p103f"
		/// </seealso>
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
					u  = new GF2nONBElement(this, this.random);
					ut = new GF2nPolynomial(2, GF2nONBElement.ZERO(this));

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
				throw new ArgumentException("GF2nField.computeCOBMatrix: B1 has a " + "different degree and thus cannot be coverted to!");
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

			gamma = new GF2nPolynomialElement[this.mDegree];

			// build gamma matrix by squaring
			gamma[0] = (GF2nElement) u.clone();

			for(i = 1; i < this.mDegree; i++) {
				gamma[i] = gamma[i - 1].square();
			}

			// convert horizontal gamma matrix by vertical Bitstrings
			for(i = 0; i < this.mDegree; i++) {
				for(j = 0; j < this.mDegree; j++) {
					if(gamma[i].testBit(j)) {
						COBMatrix[this.mDegree - j - 1].Bit = this.mDegree - i - 1;
					}
				}
			}

			this.fields.Add(B1);
			this.matrices.Add(COBMatrix);
			B1.fields.Add(this);
			B1.matrices.Add(this.invertMatrix(COBMatrix));
		}

		/// <summary>
		///     Computes the field polynomial for a ONB according to IEEE 1363 A.7.2
		///     (p110f).
		/// </summary>
		/// <seealso cref="P1363 A.7.2, p110f"
		/// </seealso>
		protected internal override void computeFieldPolynomial() {
			if(this.mType == 1) {
				this.fieldPolynomial = new GF2Polynomial(this.mDegree + 1, "ALL");
			} else if(this.mType == 2) {
				// 1. q = 1
				GF2Polynomial q = new GF2Polynomial(this.mDegree + 1, "ONE");

				// 2. p = t+1
				GF2Polynomial p = new GF2Polynomial(this.mDegree + 1, "X");
				p.addToThis(q);
				GF2Polynomial r;
				int           i;

				// 3. for i = 1 to (m-1) do
				for(i = 1; i < this.mDegree; i++) {
					// r <- q
					r = q;

					// q <- p
					q = p;

					// p = tq+r
					p = q.shiftLeft();
					p.addToThis(r);
				}

				this.fieldPolynomial = p;
			}
		}

		/// <summary>
		///     Compute the inverse of a matrix <tt>a</tt>.
		/// </summary>
		/// <param name="a"> the matrix </param>
		/// <returns>
		///     <tt>a<sup>-1</sup></tt>
		/// </returns>
		internal virtual int[][] invMatrix(int[][] a) {

			int[][] A = SquareArrays.ReturnRectangularIntArray(this.mDegree, this.mDegree);
			A = a;

			int[][] inv = SquareArrays.ReturnRectangularIntArray(this.mDegree, this.mDegree);

			for(int i = 0; i < this.mDegree; i++) {
				inv[i][i] = 1;
			}

			for(int i = 0; i < this.mDegree; i++) {
				for(int j = i; j < this.mDegree; j++) {
					A[this.mDegree - 1 - i][j] = A[i][i];
				}
			}

			return null;
		}

		private void computeType() {
			if((this.mDegree & 7) == 0) {
				throw new Exception("The extension degree is divisible by 8!");
			}

			// checking for the type
			int s = 0;
			int k = 0;
			this.mType = 1;

			for(int d = 0; d != 1; this.mType++) {
				s = (this.mType * this.mDegree) + 1;

				if(IntegerFunctions.isPrime(s)) {
					k = IntegerFunctions.order(2, s);
					d = IntegerFunctions.Gcd((this.mType * this.mDegree) / k, this.mDegree);
				}
			}

			this.mType--;

			if(this.mType == 1) {
				s = (this.mDegree << 1) + 1;

				if(IntegerFunctions.isPrime(s)) {
					k = IntegerFunctions.order(2, s);
					int d = IntegerFunctions.Gcd((this.mDegree << 1) / k, this.mDegree);

					if(d == 1) {
						this.mType++;
					}
				}
			}
		}

		private void computeMultMatrix() {

			if((this.mType & 7) != 0) {
				int p = (this.mType * this.mDegree) + 1;

				// compute sequence F[1] ... F[p-1] via A.3.7. of 1363.
				// F[0] will not be filled!
				//
				int[] F = new int[p];

				int u;

				if(this.mType == 1) {
					u = 1;
				} else if(this.mType == 2) {
					u = p - 1;
				} else {
					u = this.elementOfOrder(this.mType, p);
				}

				int w = 1;
				int n;

				for(int j = 0; j < this.mType; j++) {
					n = w;

					for(int i = 0; i < this.mDegree; i++) {
						F[n] = i;
						n    = (n << 1) % p;

						if(n < 0) {
							n += p;
						}
					}

					w = (u * w) % p;

					if(w < 0) {
						w += p;
					}
				}

				// building the matrix (mDegree * 2)
				//
				if(this.mType == 1) {
					for(int k = 1; k < (p - 1); k++) {
						if(this.mMult[F[k + 1]][0] == -1) {
							this.mMult[F[k + 1]][0] = F[p - k];
						} else {
							this.mMult[F[k + 1]][1] = F[p - k];
						}
					}

					int m_2 = this.mDegree >> 1;

					for(int k = 1; k <= m_2; k++) {

						if(this.mMult[k - 1][0] == -1) {
							this.mMult[k - 1][0] = (m_2 + k) - 1;
						} else {
							this.mMult[k - 1][1] = (m_2 + k) - 1;
						}

						if(this.mMult[(m_2 + k) - 1][0] == -1) {
							this.mMult[(m_2 + k) - 1][0] = k - 1;
						} else {
							this.mMult[(m_2 + k) - 1][1] = k - 1;
						}
					}
				} else if(this.mType == 2) {
					for(int k = 1; k < (p - 1); k++) {
						if(this.mMult[F[k + 1]][0] == -1) {
							this.mMult[F[k + 1]][0] = F[p - k];
						} else {
							this.mMult[F[k + 1]][1] = F[p - k];
						}
					}
				} else {
					throw new Exception("only type 1 or type 2 implemented");
				}
			} else {
				throw new Exception("bisher nur fuer Gausssche Normalbasen" + " implementiert");
			}
		}

		private int elementOfOrder(int k, int p) {
			Random random = new Random();
			int    m      = 0;

			while(m == 0) {
				m =  random.Next();
				m %= p - 1;

				if(m < 0) {
					m += p - 1;
				}
			}

			int l = IntegerFunctions.order(m, p);

			while(((l % k) != 0) || (l == 0)) {
				while(m == 0) {
					m =  random.Next();
					m %= p - 1;

					if(m < 0) {
						m += p - 1;
					}
				}

				l = IntegerFunctions.order(m, p);
			}

			int r = m;

			l = k / l;

			for(int i = 2; i <= l; i++) {
				r *= m;
			}

			return r;
		}
	}

}
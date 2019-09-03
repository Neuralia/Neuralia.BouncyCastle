using System;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class describes decoding operations of an irreducible binary Goppa code.
	///     A check matrix H of the Goppa code and an irreducible Goppa polynomial are
	///     used the operations are worked over a finite field GF(2^m)
	/// </summary>
	/// <seealso cref= GF2mField
	/// </seealso>
	/// <seealso cref= PolynomialGF2mSmallM
	/// </seealso>
	public sealed class GoppaCode {

		/// <summary>
		///     Default constructor (private).
		/// </summary>
		private GoppaCode() {
			// empty
		}

		/// <summary>
		///     Construct the check matrix of a Goppa code in canonical form from the
		///     irreducible Goppa polynomial over the finite field
		///     <tt>GF(2<sup>m</sup>)</tt>.
		/// </summary>
		/// <param name="field"> the finite field </param>
		/// <param name="gp">    the irreducible Goppa polynomial </param>
		public static GF2Matrix createCanonicalCheckMatrix(GF2mField field, PolynomialGF2mSmallM gp) {
			int m = field.Degree;
			int n = 1 << m;
			int t = gp.Degree;

			/* create matrix H over GF(2^m) */

			int[][] hArray = SquareArrays.ReturnRectangularIntArray(t, n);

			// create matrix YZ

			int[][] yz = SquareArrays.ReturnRectangularIntArray(t, n);

			for(int j = 0; j < n; j++) {
				// here j is used as index and as element of field GF(2^m)
				yz[0][j] = field.inverse(gp.evaluateAt(j));
			}

			for(int i = 1; i < t; i++) {
				for(int j = 0; j < n; j++) {
					// here j is used as index and as element of field GF(2^m)
					yz[i][j] = field.mult(yz[i - 1][j], j);
				}
			}

			// create matrix H = XYZ
			for(int i = 0; i < t; i++) {
				for(int j = 0; j < n; j++) {
					for(int k = 0; k <= i; k++) {
						hArray[i][j] = field.add(hArray[i][j], field.mult(yz[k][j], gp.getCoefficient((t + k) - i)));
					}
				}
			}

			/* convert to matrix over GF(2) */

			int[][] result = SquareArrays.ReturnRectangularIntArray(t * m, (int) ((uint) (n + 31) >> 5));

			for(int j = 0; j < n; j++) {
				int q = (int) ((uint) j >> 5);
				int r = 1 << (j & 0x1f);

				for(int i = 0; i < t; i++) {
					int e = hArray[i][j];

					for(int u = 0; u < m; u++) {
						int b = (int) ((uint) e >> u) & 1;

						if(b != 0) {
							int ind = ((i + 1) * m) - u - 1;
							result[ind][q] ^= r;
						}
					}
				}
			}

			return new GF2Matrix(n, result);
		}

		/// <summary>
		///     Given a check matrix <tt>H</tt>, compute matrices <tt>S</tt>,
		///     <tt>M</tt>, and a random permutation <tt>P</tt> such that
		///     <tt>S*H*P = (Id|M)</tt>. Return <tt>S^-1</tt>, <tt>M</tt>, and
		///     <tt>P</tt> as <seealso cref="MaMaPe" />. The matrix <tt>(Id | M)</tt> is called
		///     the systematic form of H.
		/// </summary>
		/// <param name="h">  the check matrix </param>
		/// <param name="sr"> a source of randomness </param>
		/// <returns> the tuple <tt>(S^-1, M, P)</tt> </returns>
		public static MaMaPe computeSystematicForm(GF2Matrix h, SecureRandom sr) {
			int         n = h.NumColumns;
			GF2Matrix   hp, sInv;
			GF2Matrix   s = null;
			Permutation p;
			bool        found = false;

			do {
				p    = new Permutation(n, sr);
				hp   = (GF2Matrix) h.rightMultiply(p);
				sInv = hp.LeftSubMatrix;

				try {
					found = true;
					s     = (GF2Matrix) sInv.computeInverse();

					if(s == null) {
						// not invertible
						found = false;
					}
				} catch(ArithmeticException) {
					found = false;
				}
			} while(!found);

			GF2Matrix shp = (GF2Matrix) s.rightMultiply(hp);
			GF2Matrix m   = shp.RightSubMatrix;

			return new MaMaPe(sInv, m, p);
		}

		/// <summary>
		///     Find an error vector <tt>e</tt> over <tt>GF(2)</tt> from an input
		///     syndrome <tt>s</tt> over <tt>GF(2<sup>m</sup>)</tt>.
		/// </summary>
		/// <param name="syndVec">      the syndrome </param>
		/// <param name="field">        the finite field </param>
		/// <param name="gp">           the irreducible Goppa polynomial </param>
		/// <param name="sqRootMatrix">
		///     the matrix for computing square roots in
		///     <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
		/// </param>
		/// <returns> the error vector </returns>
		public static GF2Vector syndromeDecode(GF2Vector syndVec, GF2mField field, PolynomialGF2mSmallM gp, PolynomialGF2mSmallM[] sqRootMatrix) {

			int n = 1 << field.Degree;

			// the error vector
			GF2Vector errors = new GF2Vector(n);

			// if the syndrome vector is zero, the error vector is also zero
			if(!syndVec.Zero) {
				// convert syndrome vector to polynomial over GF(2^m)
				PolynomialGF2mSmallM syndrome = new PolynomialGF2mSmallM(syndVec.toExtensionFieldVector(field));

				// compute T = syndrome^-1 mod gp
				PolynomialGF2mSmallM t = syndrome.modInverse(gp);

				// compute tau = sqRoot(T + X) mod gp
				PolynomialGF2mSmallM tau = t.addMonomial(1);
				tau = tau.modSquareRootMatrix(sqRootMatrix);

				// compute polynomials a and b satisfying a + b*tau = 0 mod gp
				PolynomialGF2mSmallM[] ab = tau.modPolynomialToFracton(gp);

				// compute the polynomial a^2 + X*b^2
				PolynomialGF2mSmallM a2        = ab[0].multiply(ab[0]);
				PolynomialGF2mSmallM b2        = ab[1].multiply(ab[1]);
				PolynomialGF2mSmallM xb2       = b2.multWithMonomial(1);
				PolynomialGF2mSmallM a2plusXb2 = a2.add(xb2);

				// normalize a^2 + X*b^2 to obtain the error locator polynomial
				int                  headCoeff    = a2plusXb2.HeadCoefficient;
				int                  invHeadCoeff = field.inverse(headCoeff);
				PolynomialGF2mSmallM elp          = a2plusXb2.multWithElement(invHeadCoeff);

				// for all elements i of GF(2^m)
				for(int i = 0; i < n; i++) {
					// evaluate the error locator polynomial at i
					int z = elp.evaluateAt(i);

					// if polynomial evaluates to zero
					if(z == 0) {
						// set the i-th coefficient of the error vector
						errors.Bit = i;
					}
				}
			}

			return errors;
		}

		/// <summary>
		///     This class is a container for two instances of <seealso cref="GF2Matrix" /> and one
		///     instance of <seealso cref="Permutation" />. It is used to hold the systematic form
		///     <tt>S*H*P = (Id|M)</tt> of the check matrix <tt>H</tt> as returned by
		///     <seealso cref="GoppaCode#computeSystematicForm(GF2Matrix, SecureRandom)" />.
		/// </summary>
		/// <seealso cref= GF2Matrix
		/// </seealso>
		/// <seealso cref= Permutation
		/// </seealso>
		public class MaMaPe {

			internal Permutation p;

			internal GF2Matrix s, h;

			/// <summary>
			///     Construct a new <seealso cref="MaMaPe" /> container with the given parameters.
			/// </summary>
			/// <param name="s"> the first matrix </param>
			/// <param name="h"> the second matrix </param>
			/// <param name="p"> the permutation </param>
			public MaMaPe(GF2Matrix s, GF2Matrix h, Permutation p) {
				this.s = s;
				this.h = h;
				this.p = p;
			}

			/// <returns> the first matrix </returns>
			public virtual GF2Matrix FirstMatrix => this.s;

			/// <returns> the second matrix </returns>
			public virtual GF2Matrix SecondMatrix => this.h;

			/// <returns> the permutation </returns>
			public virtual Permutation Permutation => this.p;
		}

		/// <summary>
		///     This class is a container for an instance of <seealso cref="GF2Matrix" /> and one
		///     int[]. It is used to hold a generator matrix and the set of indices such
		///     that the submatrix of the generator matrix consisting of the specified
		///     columns is the identity.
		/// </summary>
		/// <seealso cref= GF2Matrix
		/// </seealso>
		/// <seealso cref= Permutation
		/// </seealso>
		public class MatrixSet {

			internal GF2Matrix g;

			internal int[] setJ;

			/// <summary>
			///     Construct a new <seealso cref="MatrixSet" /> container with the given
			///     parameters.
			/// </summary>
			/// <param name="g">    the generator matrix </param>
			/// <param name="setJ">
			///     the set of indices such that the submatrix of the
			///     generator matrix consisting of the specified columns
			///     is the identity
			/// </param>
			public MatrixSet(GF2Matrix g, int[] setJ) {
				this.g    = g;
				this.setJ = setJ;
			}

			/// <returns> the generator matrix </returns>
			public virtual GF2Matrix G => this.g;

			/// <returns>
			///     the set of indices such that the submatrix of the generator
			///     matrix consisting of the specified columns is the identity
			/// </returns>
			public virtual int[] SetJ => this.setJ;
		}
	}

}
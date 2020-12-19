namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {
	public interface IPolynomial {

		/// <summary>
		///     Multiplies the polynomial by an <code>IntegerPolynomial</code>,
		///     taking the indices mod <code>N</code>.
		/// </summary>
		/// <param name="poly2"> a polynomial </param>
		/// <returns> the product of the two polynomials </returns>
		IntegerPolynomial mult(IntegerPolynomial poly2);

		/// <summary>
		///     Multiplies the polynomial by an <code>IntegerPolynomial</code>,
		///     taking the coefficient values mod <code>modulus</code> and the indices mod <code>N</code>.
		/// </summary>
		/// <param name="poly2">   a polynomial </param>
		/// <param name="modulus"> a modulus to apply </param>
		/// <returns> the product of the two polynomials </returns>
		IntegerPolynomial mult(IntegerPolynomial poly2, int modulus);

		/// <summary>
		///     Returns a polynomial that is equal to this polynomial (in the sense that
		///     <seealso cref="#mult(IntegerPolynomial, int)" />
		///     returns equal <code>IntegerPolynomial</code>s). The new polynomial is guaranteed to be independent of the original.
		/// </summary>
		/// <returns> a new <code>IntegerPolynomial</code>. </returns>
		IntegerPolynomial toIntegerPolynomial();

		/// <summary>
		///     Multiplies the polynomial by a <code>BigIntPolynomial</code>, taking the indices mod N. Does not
		///     change this polynomial but returns the result as a new polynomial.
		///     <br>
		///         Both polynomials must have the same number of coefficients.
		/// </summary>
		/// <param name="poly2"> the polynomial to multiply by </param>
		/// <returns> a new polynomial </returns>
		BigIntPolynomial mult(BigIntPolynomial poly2);
	}

}
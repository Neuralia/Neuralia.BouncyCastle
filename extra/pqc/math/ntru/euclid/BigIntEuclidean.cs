using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.euclid {

	/// <summary>
	///     Extended Euclidean Algorithm in <code>BigInteger</code>s
	/// </summary>
	public class BigIntEuclidean {
		public BigInteger x, y, gcd;

		private BigIntEuclidean() {
		}

		/// <summary>
		///     Runs the EEA on two <code>BigInteger</code>s
		///     <br>
		///         Implemented from pseudocode on
		///         <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Wikipedia</a>.
		/// </summary>
		/// <param name="a"> </param>
		/// <param name="b"> </param>
		/// <returns>
		///     a <code>BigIntEuclidean</code> object that contains the result in the variables <code>x</code>,
		///     <code>y</code>, and <code>gcd</code>
		/// </returns>
		public static BigIntEuclidean calculate(BigInteger a, BigInteger b) {
			BigInteger x     = BigInteger.Zero;
			BigInteger lastx = BigInteger.One;
			BigInteger y     = BigInteger.One;
			BigInteger lasty = BigInteger.Zero;

			while(!b.Equals(BigInteger.Zero)) {
				BigInteger[] quotientAndRemainder = a.DivideAndRemainder(b);
				BigInteger   quotient             = quotientAndRemainder[0];

				BigInteger temp = a;
				a = b;
				b = quotientAndRemainder[1];

				temp  = x;
				x     = lastx.Subtract(quotient.Multiply(x));
				lastx = temp;

				temp  = y;
				y     = lasty.Subtract(quotient.Multiply(y));
				lasty = temp;
			}

			BigIntEuclidean result = new BigIntEuclidean();
			result.x   = lastx;
			result.y   = lasty;
			result.gcd = a;

			return result;
		}
	}
}
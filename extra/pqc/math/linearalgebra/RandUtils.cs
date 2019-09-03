

using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	public class RandUtils {
		internal static int nextInt(SecureRandom rand, int n) {

			if((n & -n) == n) // i.e., n is a power of 2
			{
				return (int) ((n * (long) (int) ((uint) rand.Next() >> 1)) >> 31);
			}

			int bits, value;

			do {
				bits  = (int) ((uint) rand.Next() >> 1);
				value = bits % n;
			} while(((bits - value) + (n - 1)) < 0);

			return value;
		}
	}

}
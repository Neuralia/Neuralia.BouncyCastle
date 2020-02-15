using System;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.Security {
	/// <summary>
	/// A class that fixes bugs in the bouncy SecureRandom class.
	/// </summary>
	public class BetterSecureRandom : SecureRandom {

		public BetterSecureRandom() {
		}

		public BetterSecureRandom(byte[] seed) : base(seed) {
		}

		public BetterSecureRandom(IRandomGenerator generator) : base(generator) {
		}

		/// <summary>
		/// fix bugs in the parent version when a number can be negative and thus smaller than minValue
		/// </summary>
		/// <param name="minValue"></param>
		/// <param name="maxValue"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentException"></exception>
		public override int Next(int minValue, int maxValue) {
			if (maxValue <= minValue)
			{
				if (maxValue == minValue)
					return minValue;

				throw new ArgumentException("maxValue cannot be less than minValue");
			}

			int diff = maxValue - minValue;

			if(diff > 0) {

				int result = 0;
				do {
					result = minValue + this.Next(diff);
				} while(result < minValue);

				return result;
			}

			for (;;)
			{
				int i = this.NextInt();

				if (i >= minValue && i < maxValue)
					return i;
			}
		}
	}
}
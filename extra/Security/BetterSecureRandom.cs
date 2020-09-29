using System;
using Neuralia.Blockchains.Tools.Cryptography;
using Neuralia.Blockchains.Tools.Serialization;
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

		public override int Next(int maxValue) {

			return GlobalRandom.GetNext(maxValue);
		}
		
		/// <summary>
		/// fix bugs in the parent version when a number can be negative and thus smaller than minValue
		/// </summary>
		/// <param name="minValue"></param>
		/// <param name="maxValue"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentException"></exception>
		public override int Next(int minValue, int maxValue) {
			return GlobalRandom.GetNext(minValue, maxValue);
		}

		public override int NextInt() {

			byte[] bytes = new byte[sizeof(int)];
			this.NextBytes(bytes);

			TypeSerializer.Deserialize(bytes.AsSpan(), out int result);
			
			return result;
		}

		public override long NextLong() {
			byte[] bytes = new byte[sizeof(long)];
			this.NextBytes(bytes);

			TypeSerializer.Deserialize(bytes.AsSpan(), out long result);
			
			return result;
		}
	}
}
using System.Collections.Generic;
using System.Numerics;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.util {
	public static class Extensions {
		public static int NumberOfLeadingZeros(int x) {
			const int numIntBits = sizeof(int) * 8; //compile time constant

			//do the smearing
			x |= x >> 1;
			x |= x >> 2;
			x |= x >> 4;
			x |= x >> 8;
			x |= x >> 16;

			//count the ones
			x -= (x >> 1) & 0x55555555;
			x =  ((x >> 2) & 0x33333333) + (x & 0x33333333);
			x =  ((x >> 4) + x) & 0x0f0f0f0f;
			x += x >> 8;
			x += x >> 16;

			return numIntBits - (x & 0x0000003f); //subtract # of 1s from 32
		}

		public static BigInteger ValueOf(this BigInteger integer, long value) {
			return new BigInteger(value);
		}

		/// <summary>
		///     Shuffle an array using the SecureRandom class
		/// </summary>
		/// <typeparam name="T">Type of array</typeparam>
		/// <param name="Source">The list instance</param>
		public static void Shuffle<T>(this T[] Source) {
			SecureRandom rnd = new SecureRandom();

			Shuffle(Source, rnd);
		}

		/// <summary>
		///     Shuffle an array with a specific Prng class
		/// </summary>
		/// <typeparam name="T">Type of list</typeparam>
		/// <param name="Source">The list instance</param>
		/// <param name="Rng">The pseudo random generator</param>
		public static void Shuffle<T>(this T[] Source, SecureRandom Rng) {
			for(int i = 0; i < Source.Length; i++) {
				int index = Rng.Next(0, Source.Length - 1);
				T   temp  = Source[i];
				Source[i]     = Source[index];
				Source[index] = temp;
			}
		}

		public static void Shuffle<T>(this IList<T> Source, SecureRandom Rng) {
			for(int i = 0; i < Source.Count; i++) {
				int index = Rng.Next(0, Source.Count - 1);
				T   temp  = Source[i];
				Source[i]     = Source[index];
				Source[index] = temp;
			}
		}
	}
}
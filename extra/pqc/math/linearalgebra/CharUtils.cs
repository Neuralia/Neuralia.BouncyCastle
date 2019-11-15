using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	public sealed class CharUtils {

		/// <summary>
		///     Default constructor (private)
		/// </summary>
		private CharUtils() {
			// empty
		}

		/// <summary>
		///     Return a clone of the given char array. No null checks are performed.
		/// </summary>
		/// <param name="array"> the array to clone </param>
		/// <returns> the clone of the given array </returns>
		public static char[] clone(char[] array) {
			char[] result = new char[array.Length];
			Array.Copy(array, 0, result, 0, array.Length);

			return result;
		}

		/// <summary>
		///     Convert the given char array into a byte array.
		/// </summary>
		/// <param name="chars"> the char array </param>
		/// <returns> the converted array </returns>
		public static SafeArrayHandle toByteArray(char[] chars) {
			SafeArrayHandle result = ByteArray.Create(chars.Length);

			for(int i = chars.Length - 1; i >= 0; i--) {
				result[i] = (byte) chars[i];
			}

			return result;
		}

		/// <summary>
		///     Convert the given char array into a
		///     byte array for use with PBE encryption.
		/// </summary>
		/// <param name="chars"> the char array </param>
		/// <returns> the converted array </returns>
		public static SafeArrayHandle toByteArrayForPBE(char[] chars) {

			SafeArrayHandle @out = ByteArray.Create(chars.Length);

			for(int i = 0; i < chars.Length; i++) {
				@out[i] = (byte) chars[i];
			}

			int         length = @out.Length * 2;
			SafeArrayHandle ret    = ByteArray.Create(length + 2);

			int j = 0;

			for(int i = 0; i < @out.Length; i++) {
				j          = i * 2;
				ret[j]     = 0;
				ret[j + 1] = @out[i];
			}

			ret[length]     = 0;
			ret[length + 1] = 0;

			return ret;
		}

		/// <summary>
		///     Compare two char arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the char byte array </param>
		/// <param name="right"> the second char array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(char[] left, char[] right) {
			if(left.Length != right.Length) {
				return false;
			}

			bool result = true;

			for(int i = left.Length - 1; i >= 0; i--) {
				result &= left[i] == right[i];
			}

			return result;
		}
	}

}
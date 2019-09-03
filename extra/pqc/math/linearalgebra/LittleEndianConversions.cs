using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	/// <summary>
	///     This is a utility class containing data type conversions using little-endian
	///     byte order.
	/// </summary>
	/// <seealso cref= BigEndianConversions
	/// </seealso>
	public sealed class LittleEndianConversions {

		/// <summary>
		///     Default constructor (private).
		/// </summary>
		private LittleEndianConversions() {
			// empty
		}

		/// <summary>
		///     Convert an octet string of length 4 to an integer. No length checking is
		///     performed.
		/// </summary>
		/// <param name="input"> the byte array holding the octet string </param>
		/// <returns> an integer representing the octet string <tt>input</tt> </returns>
		/// <exception cref="ArithmeticException"> if the length of the given octet string is larger than 4. </exception>
		public static int OS2IP(IByteArray input) {
			return (input[0] & 0xff) | ((input[1] & 0xff) << 8) | ((input[2] & 0xff) << 16) | ((input[3] & 0xff) << 24);
		}

		/// <summary>
		///     Convert an byte array of length 4 beginning at <tt>offset</tt> into an
		///     integer.
		/// </summary>
		/// <param name="input"> the byte array </param>
		/// <param name="inOff"> the offset into the byte array </param>
		/// <returns> the resulting integer </returns>
		public static int OS2IP(IByteArray input, int inOff) {
			int result = input[inOff++] & 0xff;
			result |= (input[inOff++]   & 0xff) << 8;
			result |= (input[inOff++]   & 0xff) << 16;
			result |= (input[inOff]     & 0xff) << 24;

			return result;
		}

		/// <summary>
		///     Convert a byte array of the given length beginning at <tt>offset</tt>
		///     into an integer.
		/// </summary>
		/// <param name="input"> the byte array </param>
		/// <param name="inOff"> the offset into the byte array </param>
		/// <param name="inLen"> the length of the encoding </param>
		/// <returns> the resulting integer </returns>
		public static int OS2IP(IByteArray input, int inOff, int inLen) {
			int result = 0;

			for(int i = inLen - 1; i >= 0; i--) {
				result |= (input[inOff + i] & 0xff) << (8 * i);
			}

			return result;
		}

		/// <summary>
		///     Convert a byte array of length 8 beginning at <tt>inOff</tt> into a
		///     long integer.
		/// </summary>
		/// <param name="input"> the byte array </param>
		/// <param name="inOff"> the offset into the byte array </param>
		/// <returns> the resulting long integer </returns>
		public static long OS2LIP(IByteArray input, int inOff) {
			long result = input[inOff++]     & 0xff;
			result |= (input[inOff++]        & 0xff) << 8;
			result |= (input[inOff++]        & 0xff) << 16;
			result |= ((long) input[inOff++] & 0xff) << 24;
			result |= ((long) input[inOff++] & 0xff) << 32;
			result |= ((long) input[inOff++] & 0xff) << 40;
			result |= ((long) input[inOff++] & 0xff) << 48;
			result |= ((long) input[inOff++] & 0xff) << 56;

			return result;
		}

		/// <summary>
		///     Convert an integer to an octet string of length 4.
		/// </summary>
		/// <param name="x"> the integer to convert </param>
		/// <returns> the converted integer </returns>
		public static IByteArray I2OSP(int x) {
			IByteArray result = MemoryAllocators.Instance.cryptoAllocator.Take(4);
			result[0] = (byte) x;
			result[1] = (byte) (int) ((uint) x >> 8);
			result[2] = (byte) (int) ((uint) x >> 16);
			result[3] = (byte) (int) ((uint) x >> 24);

			return result;
		}

		/// <summary>
		///     Convert an integer into a byte array beginning at the specified offset.
		/// </summary>
		/// <param name="value">  the integer to convert </param>
		/// <param name="output"> the byte array to hold the result </param>
		/// <param name="outOff"> the integer offset into the byte array </param>
		public static void I2OSP(int value, IByteArray output, int outOff) {
			output[outOff++] = (byte) value;
			output[outOff++] = (byte) (int) ((uint) value >> 8);
			output[outOff++] = (byte) (int) ((uint) value >> 16);
			output[outOff++] = (byte) (int) ((uint) value >> 24);
		}

		/// <summary>
		///     Convert an integer to a byte array beginning at the specified offset. No
		///     length checking is performed (i.e., if the integer cannot be encoded with
		///     <tt>length</tt> octets, it is truncated).
		/// </summary>
		/// <param name="value">  the integer to convert </param>
		/// <param name="output"> the byte array to hold the result </param>
		/// <param name="outOff"> the integer offset into the byte array </param>
		/// <param name="outLen"> the length of the encoding </param>
		public static void I2OSP(int value, IByteArray output, int outOff, int outLen) {
			for(int i = outLen - 1; i >= 0; i--) {
				output[outOff + i] = (byte) (int) ((uint) value >> (8 * i));
			}
		}

		/// <summary>
		///     Convert an integer to a byte array of length 8.
		/// </summary>
		/// <param name="input"> the integer to convert </param>
		/// <returns> the converted integer </returns>
		public static IByteArray I2OSP(long input) {
			IByteArray output = MemoryAllocators.Instance.cryptoAllocator.Take(8);
			output[0] = (byte) input;
			output[1] = (byte) (long) ((ulong) input >> 8);
			output[2] = (byte) (long) ((ulong) input >> 16);
			output[3] = (byte) (long) ((ulong) input >> 24);
			output[4] = (byte) (long) ((ulong) input >> 32);
			output[5] = (byte) (long) ((ulong) input >> 40);
			output[6] = (byte) (long) ((ulong) input >> 48);
			output[7] = (byte) (long) ((ulong) input >> 56);

			return output;
		}

		/// <summary>
		///     Convert an integer to a byte array of length 8.
		/// </summary>
		/// <param name="input">  the integer to convert </param>
		/// <param name="output"> byte array holding the output </param>
		/// <param name="outOff"> offset in output array where the result is stored </param>
		public static void I2OSP(long input, IByteArray output, int outOff) {
			output[outOff++] = (byte) input;
			output[outOff++] = (byte) (long) ((ulong) input >> 8);
			output[outOff++] = (byte) (long) ((ulong) input >> 16);
			output[outOff++] = (byte) (long) ((ulong) input >> 24);
			output[outOff++] = (byte) (long) ((ulong) input >> 32);
			output[outOff++] = (byte) (long) ((ulong) input >> 40);
			output[outOff++] = (byte) (long) ((ulong) input >> 48);
			output[outOff]   = (byte) (long) ((ulong) input >> 56);
		}

		/// <summary>
		///     Convert an int array to a byte array of the specified length. No length
		///     checking is performed (i.e., if the last integer cannot be encoded with
		///     <tt>length % 4</tt> octets, it is truncated).
		/// </summary>
		/// <param name="input">  the int array </param>
		/// <param name="outLen"> the length of the converted array </param>
		/// <returns> the converted array </returns>
		public static IByteArray toByteArray(int[] input, int outLen) {
			int         intLen = input.Length;
			IByteArray result = MemoryAllocators.Instance.cryptoAllocator.Take(outLen);
			int         index  = 0;

			for(int i = 0; i <= (intLen - 2); i++, index += 4) {
				I2OSP(input[i], result, index);
			}

			I2OSP(input[intLen - 1], result, index, outLen - index);

			return result;
		}

		/// <summary>
		///     Convert a byte array to an int array.
		/// </summary>
		/// <param name="input"> the byte array </param>
		/// <returns> the converted array </returns>
		public static int[] toIntArray(IByteArray input) {
			int   intLen  = (input.Length + 3) / 4;
			int   lastLen = input.Length & 0x03;
			int[] result  = new int[intLen];

			int index = 0;

			for(int i = 0; i <= (intLen - 2); i++, index += 4) {
				result[i] = OS2IP(input, index);
			}

			if(lastLen != 0) {
				result[intLen - 1] = OS2IP(input, index, lastLen);
			} else {
				result[intLen - 1] = OS2IP(input, index);
			}

			return result;
		}
	}

}
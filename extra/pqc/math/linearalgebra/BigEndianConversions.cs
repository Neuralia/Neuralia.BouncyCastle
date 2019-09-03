using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This is a utility class containing data type conversions using big-endian
	///     byte order.
	/// </summary>
	/// <seealso cref= LittleEndianConversions
	/// </seealso>
	public sealed class BigEndianConversions {

		/// <summary>
		///     Default constructor (private).
		/// </summary>
		private BigEndianConversions() {
			// empty
		}

		/// <summary>
		///     Convert an integer to an octet string of length 4 according to IEEE 1363,
		///     Section 5.5.3.
		/// </summary>
		/// <param name="x"> the integer to convert </param>
		/// <returns> the converted integer </returns>
		public static IByteArray I2OSP(int x) {
			IByteArray result = MemoryAllocators.Instance.cryptoAllocator.Take(4);
			result[0] = (byte) (int) ((uint) x >> 24);
			result[1] = (byte) (int) ((uint) x >> 16);
			result[2] = (byte) (int) ((uint) x >> 8);
			result[3] = (byte) x;

			return result;
		}

		/// <summary>
		///     Convert an integer to an octet string according to IEEE 1363, Section
		///     5.5.3. Length checking is performed.
		/// </summary>
		/// <param name="x">    the integer to convert </param>
		/// <param name="oLen"> the desired length of the octet string </param>
		/// <returns>
		///     an octet string of length <tt>oLen</tt> representing the
		///     integer <tt>x</tt>, or <tt>null</tt> if the integer is
		///     negative
		/// </returns>
		/// <exception cref="ArithmeticException">
		///     if <tt>x</tt> can't be encoded into <tt>oLen</tt>
		///     octets.
		/// </exception>
		public static IByteArray I2OSP(int x, int oLen) {
			if(x < 0) {
				return null;
			}

			int octL = IntegerFunctions.ceilLog256(x);

			if(octL > oLen) {
				throw new ArithmeticException("Cannot encode given integer into specified number of octets.");
			}

			IByteArray result = MemoryAllocators.Instance.cryptoAllocator.Take(oLen);

			for(int i = oLen - 1; i >= (oLen - octL); i--) {
				result[i] = (byte) (int) ((uint) x >> (8 * (oLen - 1 - i)));
			}

			return result;
		}

		/// <summary>
		///     Convert an integer to an octet string of length 4 according to IEEE 1363,
		///     Section 5.5.3.
		/// </summary>
		/// <param name="input">  the integer to convert </param>
		/// <param name="output"> byte array holding the output </param>
		/// <param name="outOff"> offset in output array where the result is stored </param>
		public static void I2OSP(int input, IByteArray output, int outOff) {
			output[outOff++] = (byte) (int) ((uint) input >> 24);
			output[outOff++] = (byte) (int) ((uint) input >> 16);
			output[outOff++] = (byte) (int) ((uint) input >> 8);
			output[outOff]   = (byte) input;
		}

		/// <summary>
		///     Convert an integer to an octet string of length 8 according to IEEE 1363,
		///     Section 5.5.3.
		/// </summary>
		/// <param name="input"> the integer to convert </param>
		/// <returns> the converted integer </returns>
		public static IByteArray I2OSP(long input) {
			IByteArray output = MemoryAllocators.Instance.cryptoAllocator.Take(8);
			output[0] = (byte) (long) ((ulong) input >> 56);
			output[1] = (byte) (long) ((ulong) input >> 48);
			output[2] = (byte) (long) ((ulong) input >> 40);
			output[3] = (byte) (long) ((ulong) input >> 32);
			output[4] = (byte) (long) ((ulong) input >> 24);
			output[5] = (byte) (long) ((ulong) input >> 16);
			output[6] = (byte) (long) ((ulong) input >> 8);
			output[7] = (byte) input;

			return output;
		}

		/// <summary>
		///     Convert an integer to an octet string of length 8 according to IEEE 1363,
		///     Section 5.5.3.
		/// </summary>
		/// <param name="input">  the integer to convert </param>
		/// <param name="output"> byte array holding the output </param>
		/// <param name="outOff"> offset in output array where the result is stored </param>
		public static void I2OSP(long input, IByteArray output, int outOff) {
			output[outOff++] = (byte) (long) ((ulong) input >> 56);
			output[outOff++] = (byte) (long) ((ulong) input >> 48);
			output[outOff++] = (byte) (long) ((ulong) input >> 40);
			output[outOff++] = (byte) (long) ((ulong) input >> 32);
			output[outOff++] = (byte) (long) ((ulong) input >> 24);
			output[outOff++] = (byte) (long) ((ulong) input >> 16);
			output[outOff++] = (byte) (long) ((ulong) input >> 8);
			output[outOff]   = (byte) input;
		}

		/// <summary>
		///     Convert an integer to an octet string of the specified length according
		///     to IEEE 1363, Section 5.5.3. No length checking is performed (i.e., if
		///     the integer cannot be encoded into <tt>length</tt> octets, it is
		///     truncated).
		/// </summary>
		/// <param name="input">  the integer to convert </param>
		/// <param name="output"> byte array holding the output </param>
		/// <param name="outOff"> offset in output array where the result is stored </param>
		/// <param name="length"> the length of the encoding </param>
		public static void I2OSP(int input, IByteArray output, int outOff, int length) {
			for(int i = length - 1; i >= 0; i--) {
				output[outOff + i] = (byte) (int) ((uint) input >> (8 * (length - 1 - i)));
			}
		}

		/// <summary>
		///     Convert an octet string to an integer according to IEEE 1363, Section
		///     5.5.3.
		/// </summary>
		/// <param name="input"> the byte array holding the octet string </param>
		/// <returns>
		///     an integer representing the octet string <tt>input</tt>, or
		///     <tt>0</tt> if the represented integer is negative or too large
		///     or the byte array is empty
		/// </returns>
		/// <exception cref="ArithmeticException"> if the length of the given octet string is larger than 4. </exception>
		public static int OS2IP(IByteArray input) {
			if(input.Length > 4) {
				throw new ArithmeticException("invalid input length");
			}

			if(input.Length == 0) {
				return 0;
			}

			int result = 0;

			for(int j = 0; j < input.Length; j++) {
				result |= (input[j] & 0xff) << (8 * (input.Length - 1 - j));
			}

			return result;
		}

		/// <summary>
		///     Convert a byte array of length 4 beginning at <tt>offset</tt> into an
		///     integer.
		/// </summary>
		/// <param name="input"> the byte array </param>
		/// <param name="inOff"> the offset into the byte array </param>
		/// <returns> the resulting integer </returns>
		public static int OS2IP(IByteArray input, int inOff) {
			int result = (input[inOff++] & 0xff) << 24;
			result |= (input[inOff++] & 0xff) << 16;
			result |= (input[inOff++] & 0xff) << 8;
			result |= input[inOff] & 0xff;

			return result;
		}

		/// <summary>
		///     Convert an octet string to an integer according to IEEE 1363, Section
		///     5.5.3.
		/// </summary>
		/// <param name="input"> the byte array holding the octet string </param>
		/// <param name="inOff">
		///     the offset in the input byte array where the octet string
		///     starts
		/// </param>
		/// <param name="inLen"> the length of the encoded integer </param>
		/// <returns>
		///     an integer representing the octet string <tt>bytes</tt>, or
		///     <tt>0</tt> if the represented integer is negative or too large
		///     or the byte array is empty
		/// </returns>
		public static int OS2IP(IByteArray input, int inOff, int inLen) {
			if((input.Length == 0) || (input.Length < ((inOff + inLen) - 1))) {
				return 0;
			}

			int result = 0;

			for(int j = 0; j < inLen; j++) {
				result |= (input[inOff + j] & 0xff) << (8 * (inLen - j - 1));
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
			long result = ((long) input[inOff++] & 0xff) << 56;
			result |= ((long) input[inOff++] & 0xff) << 48;
			result |= ((long) input[inOff++] & 0xff) << 40;
			result |= ((long) input[inOff++] & 0xff) << 32;
			result |= ((long) input[inOff++] & 0xff) << 24;
			result |= (input[inOff++]        & 0xff) << 16;
			result |= (input[inOff++]        & 0xff) << 8;
			result |= input[inOff] & 0xff;

			return result;
		}

		/// <summary>
		///     Convert an int array into a byte array.
		/// </summary>
		/// <param name="input"> the int array </param>
		/// <returns> the converted array </returns>
		public static IByteArray toByteArray(int[] input) {
			IByteArray result = MemoryAllocators.Instance.cryptoAllocator.Take(input.Length << 2);

			for(int i = 0; i < input.Length; i++) {
				I2OSP(input[i], result, i << 2);
			}

			return result;
		}

		/// <summary>
		///     Convert an int array into a byte array of the specified length. No length
		///     checking is performed (i.e., if the last integer cannot be encoded into
		///     <tt>length % 4</tt> octets, it is truncated).
		/// </summary>
		/// <param name="input">  the int array </param>
		/// <param name="length"> the length of the converted array </param>
		/// <returns> the converted array </returns>
		public static IByteArray toByteArray(int[] input, int length) {

			int         intLen = input.Length;
			IByteArray result = MemoryAllocators.Instance.cryptoAllocator.Take(length);
			int         index  = 0;

			for(int i = 0; i <= (intLen - 2); i++, index += 4) {
				I2OSP(input[i], result, index);
			}

			I2OSP(input[intLen - 1], result, index, length - index);

			return result;
		}

		/// <summary>
		///     Convert a byte array into an int array.
		/// </summary>
		/// <param name="input"> the byte array </param>
		/// <returns> the converted array </returns>
		public static int[] toIntArray(IByteArray input) {

			int intLen = (input.Length + 3) / 4;

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
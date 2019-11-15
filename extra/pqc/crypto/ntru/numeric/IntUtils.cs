using System;
using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;

#region License Information

// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#endregion

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric {
    /// <summary>
    ///     An integer utilities class
    /// </summary>
    internal static class IntUtils {

	#region Constants

		internal const  long   INFLATED          = long.MinValue;
		internal static double DOUBLE_MAX        = double.MaxValue;
		internal static double NEGATIVE_INFINITY = -1.0 / 0.0;
		internal static double NaN               = 0.0d / 0.0;
		internal static double POSITIVE_INFINITY = 1.0  / 0.0;
		internal static long   SIGNIF_BIT_MASK   = 0x000FFFFFFFFFFFFFL;
		internal static long   SIGN_BIT_MASK     = unchecked((long) 0x8000000000000000L);

	#endregion

	#region Enums

		internal enum CharConsts {
			MIN_RADIX = 2,
			MAX_RADIX = 36
		}

		internal enum DoubleConsts {
			EXP_BIAS          = 1023,
			SIZE              = 64,
			MAX_EXPONENT      = 1023,
			MIN_EXPONENT      = -1022,
			SIGNIFICAND_WIDTH = 53
		}

		internal enum FloatConsts {
			EXP_BIAS          = 127,
			MAX_EXPONENT      = 127,
			MIN_EXPONENT      = -126,
			SIGN_BIT_MASK     = unchecked((int) 0x80000000),
			SIGNIF_BIT_MASK   = 0x007FFFFF,
			SIGNIFICAND_WIDTH = 24,
			SIZE              = 32
		}

		internal enum IntConsts {
			MIN_VALUE = unchecked((int) 0x80000000),
			MAX_VALUE = 0x7fffffff,
			SIZE      = 32
		}

		internal enum LongConsts : long {
			SIZE      = 64,
			MIN_VALUE = unchecked((long) 0x8000000000000000L),
			MAX_VALUE = 0x7fffffffffffffffL
		}

	#endregion

	#region Internal Methods

        /// <summary>
        ///     Returns the number of one-bits in the two's complement binary
        ///     representation of the specified int value.
        ///     <para>This function is sometimes referred to as the population count.</para>
        /// </summary>
        /// <param name="X">The value whose bits are to be counted</param>
        /// <returns>The number of one-bits in the two's complement binary representation of the specified int value</returns>
        internal static int BitCount(int X) {
			X = X - ((int) (uint) (X >> 1) & 0x55555555);
			X = (X                         & 0x33333333) + ((int) (uint) (X >> 2) & 0x33333333);
			X = (X + ((int) (uint) X >> 4)) & 0x0f0f0f0f;
			X = X + ((int) (uint) X >> 8);
			X = X + ((int) (uint) X >> 16);

			return X & 0x3f;
		}

        /// <summary>
        ///     Returns the number of bits in a number
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the number of bits in a number</returns>
        internal static int BitCount(long X) {
			// Successively collapse alternating bit groups into a sum.
			X = ((X >> 1) & 0x5555555555555555L) + (X & 0x5555555555555555L);
			X = ((X >> 2) & 0x3333333333333333L) + (X & 0x3333333333333333L);

			int v = (int) (URShift(X, 32) + X);
			v = ((v >> 4) & 0x0f0f0f0f) + (v & 0x0f0f0f0f);
			v = ((v >> 8) & 0x00ff00ff) + (v & 0x00ff00ff);

			return ((v >> 16) & 0x0000ffff) + (v & 0x0000ffff);
		}

        /// <summary>
        ///     Convert a double to a long value
        /// </summary>
        /// <param name="X">Double to convert</param>
        /// <returns>Long value representation</returns>
        internal static long DoubleToLong(double X) {
			if(X != X) {
				return 0L;
			}

			if(X >= 9.2233720368547758E+18) {
				return 0x7fffffffffffffffL;
			}

			if(X <= -9.2233720368547758E+18) {
				return -9223372036854775808L;
			}

			return (long) X;
		}

        /// <summary>
        ///     Copy a floats bits to an integer
        /// </summary>
        /// <param name="X">Float to convert</param>
        /// <returns>The integer</returns>
        internal static int FloatToInt(float X) {
			float[] fa = {X};
			int[]   ia = new int[1];
			Buffer.BlockCopy(fa, 0, ia, 0, 4);

			return ia[0];
		}

        /// <summary>
        ///     Returns the highest order 1 bit in a number
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the highest order 1 bit in a number</returns>
        internal static int HighestOneBit(int X) {
			X |= URShift(X, 1);
			X |= URShift(X, 2);
			X |= URShift(X, 4);
			X |= URShift(X, 8);
			X |= URShift(X, 16);

			return X ^ URShift(X, 1);
		}

        /// <summary>
        ///     Returns the highest order 1 bit in a number
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the highest order 1 bit in a number</returns>
        internal static long HighestOneBit(long X) {
			X |= URShift(X, 1);
			X |= URShift(X, 2);
			X |= URShift(X, 4);
			X |= URShift(X, 8);
			X |= URShift(X, 16);
			X |= URShift(X, 32);

			return X ^ URShift(X, 1);
		}

        /// <summary>
        ///     Copy an integer to a byte array
        /// </summary>
        /// <param name="X">Integer to copy</param>
        /// <returns>The integer bytes</returns>
        internal static ByteArray IntToBytes(int X) {
			int[]       num  = new int[1] {X};
			ByteArray data = ByteArray.Create(4);
			Buffer.BlockCopy(num, 0, data.Bytes, data.Offset, 4);

			return data;
		}

        /// <summary>
        ///     Copy an array of integers to a byte array
        /// </summary>
        /// <param name="X">Array of integers</param>
        /// <returns>The integers bytes</returns>
        internal static ByteArray IntsToBytes(int[] X) {
	        ByteArray data = ByteArray.Create(X.Length * 4);
			Buffer.BlockCopy(X, 0, data.Bytes, data.Offset, X.Length * 4);

			return data;
		}

        /// <summary>
        ///     Copy an integer bits to a float
        /// </summary>
        /// <param name="X">Integer to copy</param>
        /// <returns>The float</returns>
        internal static float IntToFloat(int X) {
			int[]   ia = {X};
			float[] fa = new float[1];
			Buffer.BlockCopy(ia, 0, fa, 0, 4);

			return fa[0];
		}

        /// <summary>
        ///     Returns the leading number of zero bits
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the number of leading zeros</returns>
        internal static int NumberOfLeadingZeros(int X) {
			X |= URShift(X, 1);
			X |= URShift(X, 2);
			X |= URShift(X, 4);
			X |= URShift(X, 8);
			X |= URShift(X, 16);

			return BitCount(~X);
		}

        /// <summary>
        ///     Returns the leading number of zero bits
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the number of leading zeros</returns>
        internal static int NumberOfLeadingZeros(long X) {
			X |= URShift(X, 1);
			X |= URShift(X, 2);
			X |= URShift(X, 4);
			X |= URShift(X, 8);
			X |= URShift(X, 16);
			X |= URShift(X, 32);

			return BitCount(~X);
		}

        /// <summary>
        ///     Returns the trailing number of zero bits
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the number of trailing zeros</returns>
        internal static int NumberOfTrailingZeros(int X) {
			return BitCount((X & -X) - 1);
		}

        /// <summary>
        ///     Returns the trailing number of zero bits
        /// </summary>
        /// <param name="X">Number to test</param>
        /// <returns>Returns the number of trailing zeros</returns>
        internal static int NumberOfTrailingZeros(long X) {
			return BitCount((X & -X) - 1);
		}

        /// <summary>
        ///     Parses the string argument as a signed decimal integer.
        /// </summary>
        /// <param name="S">A String containing the int representation to be parsed</param>
        /// <returns>The integer value represented by the argument in decimal</returns>
        internal static int ParseInt(string S) {
			return ParseInt(S, 10);
		}

        /// <summary>
        ///     Parses the string argument as a signed integer in the radix specified by the second argument.
        /// </summary>
        /// <param name="S">The String containing the integer representation to be parsed</param>
        /// <param name="Radix">The radix to be used while parsing</param>
        /// <returns>The integer represented by the string argument in the specified radix</returns>
        internal static int ParseInt(string S, int Radix) {
			if(S == null) {
				throw new FormatException("null");
			}

			if(Radix < (int) CharConsts.MIN_RADIX) {
				throw new FormatException("radix " + Radix + " less than Character.MIN_RADIX");
			}

			if(Radix > (int) CharConsts.MAX_RADIX) {
				throw new FormatException("radix " + Radix + " greater than Character.MAX_RADIX");
			}

			int  result   = 0;
			bool negative = false;
			int  i        = 0, len = S.Length;
			int  limit    = -(int) IntConsts.MAX_VALUE;
			int  multmin;
			int  digit;

			if(len > 0) {
				char firstChar = CharUtils.CharAt(S, 0);

				if(firstChar < '0') {
					// Possible leading "+" or "-"
					if(firstChar == '-') {
						negative = true;
						limit    = (int) IntConsts.MIN_VALUE;
					} else if(firstChar != '+') {
						throw new FormatException();
					}

					if(len == 1) {
						throw new FormatException("Cannot have lone + or -");
					}

					i++;
				}

				multmin = limit / Radix;

				while(i < len) {
					// Accumulating negatively avoids surprises near MAX_VALUE
					digit = (int) char.GetNumericValue(CharUtils.CharAt(S, i++));

					if(digit < 0) {
						throw new FormatException();
					}

					if(result < multmin) {
						throw new FormatException();
					}

					result *= Radix;

					if(result < (limit + digit)) {
						throw new FormatException();
					}

					result -= digit;
				}
			} else {
				throw new FormatException();
			}

			return negative ? result : -result;
		}

        /// <summary>
        ///     Read a short value (16 bits) from a stream
        /// </summary>
        /// <param name="InputStream">Stream containing the short value</param>
        /// <returns>The Int16 value</returns>
        public static int ReadShort(Stream InputStream) {
			return (InputStream.ReadByte() * 256) + InputStream.ReadByte();
		}

        /// <summary>
        ///     Reverse a byte array order and copy to an integer
        /// </summary>
        /// <param name="Data">The byte array to reverse</param>
        /// <returns>The reversed integer</returns>
        public static int ReverseBytes(ByteArray Data) {
			// make a copy
			ByteArray temp = ByteArray.Create(Data.Length);
			Data.CopyTo(temp);

			// reverse and copy to int
			Array.Reverse(temp.Bytes, temp.Offset, temp.Length);
			int[] ret = new int[1];
			Buffer.BlockCopy(temp.Bytes, temp.Offset, ret, 0, sizeof(int));

			temp.Return();

			return ret[0];
		}

        /// <summary>
        ///     Returns the value obtained by reversing the order of the bits in the
        ///     two's complement binary representation of the specified int value
        /// </summary>
        /// <param name="X">The value to be reversed</param>
        /// <returns>The value obtained by reversing order of the bits in the specified int value</returns>
        internal static int ReverseInt(int X) {
			X = (int) (((uint) (X & 0x55555555) << 1) | ((uint) (X >> 1) & 0x55555555));
			X = (int) (((uint) (X & 0x33333333) << 2) | ((uint) (X >> 2) & 0x33333333));
			X = (int) (((uint) (X & 0x0f0f0f0f) << 4) | ((uint) (X >> 4) & 0x0f0f0f0f));
			X = (X << 24) | ((X & 0xff00) << 8) | ((X >> 8) & 0xff00) | (X >> 24);

			return X;
		}

        /// <summary>
        ///     Returns the signum function of the specified long value.
        ///     <para>
        ///         The return value is -1 if the specified value is negative;
        ///         0 if the specified value is zero; and 1 if the specified value is positive.
        ///     </para>
        /// </summary>
        /// <param name="X">The value whose signum is to be computed</param>
        /// <returns>The signum function of the specified long value</returns>
        internal static int Signum(long X) {
			return (int) (((uint) X >> 63) | ((uint) -X >> 63));
		}

        /// <summary>
        ///     Operates an unsigned right shift on the given integer by the number of bits specified
        /// </summary>
        /// <param name="X">The number to shift</param>
        /// <param name="NumBits">The number of bits to shift the given number</param>
        /// <returns>
        ///     Returns an <see cref="System.Int32">int</see> representing the shifted number.
        /// </returns>
        internal static int URShift(int X, int NumBits) {
			if(X >= 0) {
				return X >> NumBits;
			}

			return (X >> NumBits) + (2 << ~NumBits);
		}

        /// <summary>
        ///     Operates an unsigned right shift on the given integer by the number of bits specified
        /// </summary>
        /// <param name="X">The number to shift</param>
        /// <param name="NumBits">The number of bits to shift the given number</param>
        /// <returns>
        ///     Returns an <see cref="System.Int64">long integer</see> representing the shifted number.
        /// </returns>
        internal static long URShift(long X, int NumBits) {
			if(X >= 0) {
				return X >> NumBits;
			}

			return (X >> NumBits) + (2L << ~NumBits);
		}

	#endregion

	}
}
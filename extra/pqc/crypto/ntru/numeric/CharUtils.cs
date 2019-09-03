#region Directives

using System;

#endregion

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
    ///     Char helper class
    /// </summary>
    internal static class CharUtils {

	#region Constants

		internal const int MIN_RADIX = 2;
		internal const int MAX_RADIX = 36;

	#endregion

	#region Methods

        /// <summary>
        ///     Get the char value at a specified index within a string
        /// </summary>
        /// <param name="Value">String to parse</param>
        /// <param name="Index">Index of value</param>
        /// <returns>Char value</returns>
        internal static char CharAt(string Value, int Index) {
			char[] ca = Value.ToCharArray();

			return ca[Index];
		}

        /// <summary>
        ///     Get the char representation of an iteger
        /// </summary>
        /// <param name="Digit">The digit to convert</param>
        /// <param name="Radix">The radix</param>
        /// <returns>New char value</returns>
        internal static char ForDigit(int Digit, int Radix) {
			if((Radix < MIN_RADIX) || (Radix > MAX_RADIX)) {
				throw new ArgumentOutOfRangeException("Bad Radix!");
			}

			if((Digit < 0) || (Digit >= Radix)) {
				throw new ArgumentOutOfRangeException("Bad Digit!");
			}

			if(Digit < 10) {
				return (char) (Digit + '0');
			}

			return (char) ((Digit - 10) + 'a');
		}

        /// <summary>
        ///     Convert a char to an integer
        /// </summary>
        /// <param name="Value">Char to convert</param>
        /// <returns>Integer representation</returns>
        internal static int ToDigit(char Value) {
			return (int) char.GetNumericValue(Value);
		}

        /// <summary>
        ///     Convert a char to an integer
        /// </summary>
        /// <param name="Value">Char to convert</param>
        /// <param name="Radix">The radix</param>
        /// <returns>New integer value</returns>
        internal static int ToDigit(char Value, int Radix) {
			if((Radix < MIN_RADIX) || (Radix > MAX_RADIX)) {
				return -1;
			}

			int digit = -1;
			Value = char.ToLowerInvariant(Value);

			if((Value >= '0') && (Value <= '9')) {
				digit = Value - '0';
			} else {
				if((Value >= 'a') && (Value <= 'z')) {
					digit = (Value - 'a') + 10;
				}
			}

			return digit < Radix ? digit : -1;
		}

        /// <summary>
        ///     Convert a string to an integer
        /// </summary>
        /// <param name="Value">String to convert</param>
        /// <returns>Integer representation</returns>
        internal static int ToDigit(string Value) {
			char[] ch = Value.ToCharArray();

			return (int) char.GetNumericValue(ch[0]);
		}

	#endregion

	}
}
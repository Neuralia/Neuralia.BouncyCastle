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
	///     MathContext RoundingModes used by BigInteger and BigDecimal
	/// </summary>
	public enum RoundingModes {
		/// <summary>
		///     Rounding mode where positive values are rounded towards positive infinity
		///     and negative values towards negative infinity.
		///     <para>Rule: <c>x.Round().Abs() >= x.Abs()</c></para>
		/// </summary>
		Up = 0,

		/// <summary>
		///     Rounding mode where the values are rounded towards zero.
		///     <para>Rule: x.Round().Abs() &lt;= x.Abs()</para>
		/// </summary>
		Down = 1,

		/// <summary>
		///     Rounding mode to round towards positive infinity.
		///     <para>
		///         For positive values this rounding mode behaves as Up, for negative values as Down.
		///         Rule: x.Round() >= x
		///     </para>
		/// </summary>
		Ceiling = 2,

		/// <summary>
		///     Rounding mode to round towards negative infinity.
		///     <para>
		///         For positive values this rounding mode behaves as Down, for negative values as Up.
		///         Rule: x.Round() &lt;= x
		///     </para>
		/// </summary>
		Floor = 3,

		/// <summary>
		///     Rounding mode where values are rounded towards the nearest neighbor.
		///     <para>Ties are broken by rounding up.</para>
		/// </summary>
		HalfUp = 4,

		/// <summary>
		///     Rounding mode where values are rounded towards the nearest neighbor.
		///     <para>Ties are broken by rounding down.</para>
		/// </summary>
		HalfDown = 5,

		/// <summary>
		///     Rounding mode where values are rounded towards the nearest neighbor.
		///     <para>Ties are broken by rounding to the even neighbor.</para>
		/// </summary>
		HalfEven = 6,

		/// <summary>
		///     Rounding mode where the rounding operations throws an ArithmeticException for
		///     the case that rounding is necessary, i.e. for the case that the value cannot be represented exactly.
		/// </summary>
		Unnecessary = 7
	}
}
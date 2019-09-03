using System;
using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;
using Org.BouncyCastle.Math;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.util {

	/// <summary>
	///     Converts a coefficient array to a compact byte array and vice versa.
	/// </summary>
	public class ArrayEncoder {
		private static readonly BigInteger THREE = BigInteger.ValueOf(3);

		/// <summary>
		///     Bit string to coefficient conversion table from P1363.1. Also found at
		///     <seealso cref="http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial" />
		///     <para>
		///         Convert each three-bit quantity to two ternary coefficients as follows, and concatenate the resulting
		///         ternary quantities to obtain [the output].
		///     </para>
		///     </para><para>
		///         <code>
		/// {0, 0, 0} -> {0, 0}<br />
		/// {0, 0, 1} -> {0, 1}<br />
		/// {0, 1, 0} -> {0, -1}<br />
		/// {0, 1, 1} -> {1, 0}<br />
		/// {1, 0, 0} -> {1, 1}<br />
		/// {1, 0, 1} -> {1, -1}<br />
		/// {1, 1, 0} -> {-1, 0}<br />
		/// {1, 1, 1} -> {-1, 1}<br />
		/// </code>
		///         </p>
		/// </summary>
		private static readonly int[] COEFF1_TABLE = {0, 0, 0, 1, 1, 1, -1, -1};

		private static readonly int[] COEFF2_TABLE = {0, 1, -1, 0, 1, -1, 0, 1};

		/// <summary>
		///     Coefficient to bit string conversion table from P1363.1. Also found at
		///     <seealso cref="http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial" />
		///     <para>
		///         Convert each set of two ternary coefficients to three bits as follows, and concatenate the resulting bit
		///         quantities to obtain [the output]:
		///     </para>
		///     </para><para>
		///         <code>
		/// {-1, -1} -> set "fail" to 1 and set bit string to {1, 1, 1}
		/// {-1, 0} -> {1, 1, 0}<br />
		/// {-1, 1} -> {1, 1, 1}<br />
		/// {0, -1} -> {0, 1, 0}<br />
		/// {0, 0} -> {0, 0, 0}<br />
		/// {0, 1} -> {0, 0, 1}<br />
		/// {1, -1} -> {1, 0, 1}<br />
		/// {1, 0} -> {0, 1, 1}<br />
		/// {1, 1} -> {1, 0, 0}<br />
		/// </code>
		///         \
		///         </p>
		/// </summary>
		private static readonly int[] BIT1_TABLE = {1, 1, 1, 0, 0, 0, 1, 0, 1};

		private static readonly int[] BIT2_TABLE = {1, 1, 1, 1, 0, 0, 0, 1, 0};
		private static readonly int[] BIT3_TABLE = {1, 0, 1, 0, 0, 1, 1, 1, 0};

		/// <summary>
		///     Encodes an int array whose elements are between 0 and <code>q</code>,
		///     to a byte array leaving no gaps between bits.
		///     <br>
		///         <code>q</code> must be a power of 2.
		/// </summary>
		/// <param name="a"> the input array </param>
		/// <param name="q"> the modulus </param>
		/// <returns> the encoded array </returns>
		public static IByteArray encodeModQ(int[] a, int q) {
			int        bitsPerCoeff = 31 - Extensions.NumberOfLeadingZeros(q);
			int        numBits      = a.Length      * bitsPerCoeff;
			int        numBytes     = (numBits + 7) / 8;
			IByteArray data         = MemoryAllocators.Instance.cryptoAllocator.Take(numBytes);
			int        bitIndex     = 0;
			int        byteIndex    = 0;

			for(int i = 0; i < a.Length; i++) {
				for(int j = 0; j < bitsPerCoeff; j++) {
					int currentBit = (a[i] >> j) & 1;
					data[byteIndex] |= (byte) (currentBit << bitIndex);

					if(bitIndex == 7) {
						bitIndex = 0;
						byteIndex++;
					} else {
						bitIndex++;
					}
				}
			}

			return data;
		}

		/// <summary>
		///     Decodes a <code>byte</code> array encoded with <seealso cref="#encodeModQ(int[], int)" /> back to an
		///     <code>int</code> array.
		///     <br>
		///         <code>N</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.
		///         <br>
		///             Ignores any excess bytes.
		/// </summary>
		/// <param name="data"> an encoded ternary polynomial </param>
		/// <param name="N">    number of coefficients </param>
		/// <param name="q"> </param>
		/// <returns> an array containing <code>N</code> coefficients between <code>0</code> and <code>q-1</code> </returns>
		public static int[] decodeModQ(IByteArray data, int N, int q) {
			int[] coeffs       = new int[N];
			int   bitsPerCoeff = 31 - Extensions.NumberOfLeadingZeros(q);
			int   numBits      = N * bitsPerCoeff;
			int   coeffIndex   = 0;

			for(int bitIndex = 0; bitIndex < numBits; bitIndex++) {
				if((bitIndex > 0) && ((bitIndex % bitsPerCoeff) == 0)) {
					coeffIndex++;
				}

				int bit = getBit(data, bitIndex);
				coeffs[coeffIndex] += bit << (bitIndex % bitsPerCoeff);
			}

			return coeffs;
		}

		/// <summary>
		///     Decodes data encoded with <seealso cref="#encodeModQ(int[], int)" /> back to an <code>int</code> array.
		///     <br>
		///         <code>N</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.
		///         <br>
		///             Ignores any excess bytes.
		/// </summary>
		/// <param name="is"> an encoded ternary polynomial </param>
		/// <param name="N">  number of coefficients </param>
		/// <param name="q"> </param>
		/// <returns> the decoded polynomial </returns>
		public static int[] decodeModQ(Stream @is, int N, int q) {
			int        qBits = 31 - Extensions.NumberOfLeadingZeros(q);
			int        size  = ((N * qBits) + 7) / 8;
			IByteArray arr   = Util.readFullLength(@is, size);

			return decodeModQ(arr, N, q);
		}

		/// <summary>
		///     Decodes a <code>byte</code> array encoded with <seealso cref="#encodeMod3Sves(int[])" /> back to an
		///     <code>int</code> array
		///     with <code>N</code> coefficients between <code>-1</code> and <code>1</code>.
		///     <br>
		///         Ignores any excess bytes.
		///         <br>
		///             See P1363.1 section 9.2.2.
		/// </summary>
		/// <param name="data"> an encoded ternary polynomial </param>
		/// <param name="N">    number of coefficients </param>
		/// <returns> the decoded coefficients </returns>
		public static int[] decodeMod3Sves(IByteArray data, int N) {
			int[] coeffs     = new int[N];
			int   coeffIndex = 0;

			for(int bitIndex = 0; bitIndex < (data.Length * 8);) {
				int bit1            = getBit(data, bitIndex++);
				int bit2            = getBit(data, bitIndex++);
				int bit3            = getBit(data, bitIndex++);
				int coeffTableIndex = (bit1 * 4) + (bit2 * 2) + bit3;
				coeffs[coeffIndex++] = COEFF1_TABLE[coeffTableIndex];
				coeffs[coeffIndex++] = COEFF2_TABLE[coeffTableIndex];

				// ignore bytes that can't fit
				if(coeffIndex > (N - 2)) {
					break;
				}
			}

			return coeffs;
		}

		/// <summary>
		///     Encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
		///     <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer <code>i</code>,
		///     so this method is only safe to use with arrays produced by <seealso cref="#decodeMod3Sves(IByteArray, int)" />.
		///     <br>
		///         See P1363.1 section 9.2.3.
		/// </summary>
		/// <param name="arr"> </param>
		/// <returns> the encoded array </returns>
		public static IByteArray encodeMod3Sves(int[] arr) {
			int        numBits   = ((arr.Length * 3) + 1) / 2;
			int        numBytes  = (numBits          + 7) / 8;
			IByteArray data      = MemoryAllocators.Instance.cryptoAllocator.Take(numBytes);
			int        bitIndex  = 0;
			int        byteIndex = 0;

			for(int i = 0; i < ((arr.Length / 2) * 2);) {
				// if length is an odd number, throw away the highest coeff
				int coeff1 = arr[i++] + 1;
				int coeff2 = arr[i++] + 1;

				if((coeff1 == 0) && (coeff2 == 0)) {
					throw new InvalidOperationException("Illegal encoding!");
				}

				int   bitTableIndex = (coeff1 * 3) + coeff2;
				int[] bits          = {BIT1_TABLE[bitTableIndex], BIT2_TABLE[bitTableIndex], BIT3_TABLE[bitTableIndex]};

				for(int j = 0; j < 3; j++) {
					data[byteIndex] |= (byte) (bits[j] << bitIndex);

					if(bitIndex == 7) {
						bitIndex = 0;
						byteIndex++;
					} else {
						bitIndex++;
					}
				}
			}

			return data;
		}

		/// <summary>
		///     Encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
		/// </summary>
		/// <returns> the encoded array </returns>
		public static IByteArray encodeMod3Tight(int[] intArray) {
			BigInteger sum = BigInteger.Zero;

			for(int i = intArray.Length - 1; i >= 0; i--) {
				sum = sum.Multiply(THREE);
				sum = sum.Add(BigInteger.ValueOf(intArray[i] + 1));
			}

			int       size = (THREE.Pow(intArray.Length).BitLength + 7) / 8;
			ByteArray arr  = sum.ToByteArray();

			if(arr.Length < size) {
				// pad with leading zeros so arr.length==size
				IByteArray arr2 = MemoryAllocators.Instance.cryptoAllocator.Take(size);
				arr2.CopyFrom(arr, 0, size - arr.Length, arr.Length);

				return arr2;
			}

			if(arr.Length > size) {
				// drop sign bit
				IByteArray arr2 = MemoryAllocators.Instance.cryptoAllocator.Take(arr.Length - 1);
				arr2.CopyFrom(arr, 1, 0, arr.Length - 1);

				return arr2;
			}

			IByteArray arr3 = MemoryAllocators.Instance.cryptoAllocator.Take(arr.Length);
			arr3.CopyFrom(arr);

			return arr3;
		}

		/// <summary>
		///     Converts a byte array produced by <seealso cref="#encodeMod3Tight(int[])" /> back to an <code>int</code> array.
		/// </summary>
		/// <param name="b"> a byte array </param>
		/// <param name="N"> number of coefficients </param>
		/// <returns> the decoded array </returns>
		public static int[] decodeMod3Tight(IByteArray b, int N) {
			BigInteger sum    = new BigInteger(1, b.ToExactByteArray());
			int[]      coeffs = new int[N];

			for(int i = 0; i < N; i++) {
				coeffs[i] = sum.Mod(THREE).IntValue - 1;

				if(coeffs[i] > 1) {
					coeffs[i] -= 3;
				}

				sum = sum.Divide(THREE);
			}

			return coeffs;
		}

		/// <summary>
		///     Converts data produced by <seealso cref="#encodeMod3Tight(int[])" /> back to an <code>int</code> array.
		/// </summary>
		/// <param name="is"> an input stream containing the data to decode </param>
		/// <param name="N">  number of coefficients </param>
		/// <returns> the decoded array </returns>
		public static int[] decodeMod3Tight(MemoryStream InputStream, int N) {
			int        size = (int) Math.Ceiling((N * Math.Log(3)) / Math.Log(2) / 8);
			IByteArray arr  = Util.readFullLength(InputStream, size);

			return decodeMod3Tight(arr, N);
		}

		private static int getBit(IByteArray arr, int bitIndex) {
			int byteIndex = bitIndex / 8;
			int arrElem   = arr[byteIndex] & 0xFF;

			return (arrElem >> (bitIndex % 8)) & 1;
		}
	}
}
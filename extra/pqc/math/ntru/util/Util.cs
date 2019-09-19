using System;
using System.Collections.Generic;
using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.euclid;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.util {

	public class Util {
		/// <summary>
		///     Calculates the inverse of n mod modulus
		/// </summary>
		public static int invert(int n, int modulus) {
			n %= modulus;

			if(n < 0) {
				n += modulus;
			}

			return IntEuclidean.calculate(n, modulus).x;
		}

		/// <summary>
		///     Calculates a^b mod modulus
		/// </summary>
		public static int pow(int a, int b, int modulus) {
			int p = 1;

			for(int i = 0; i < b; i++) {
				p = (p * a) % modulus;
			}

			return p;
		}

		/// <summary>
		///     Calculates a^b mod modulus
		/// </summary>
		public static long pow(long a, int b, long modulus) {
			long p = 1;

			for(int i = 0; i < b; i++) {
				p = (p * a) % modulus;
			}

			return p;
		}

		/// <summary>
		///     Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
		///     numNegOnes int equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N"> </param>
		/// <param name="numOnes"> </param>
		/// <param name="numNegOnes"> </param>
		/// <param name="sparse">
		///     whether to create a <seealso cref="SparseTernaryPolynomial" /> or
		///     <seealso cref="DenseTernaryPolynomial" />
		/// </param>
		/// <returns> a ternary polynomial </returns>
		public static TernaryPolynomial generateRandomTernary(int N, int numOnes, int numNegOnes, bool sparse, SecureRandom random) {
			if(sparse) {
				return SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
			}

			return DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
		}

		/// <summary>
		///     Generates an array containing numOnes ints equal to 1,
		///     numNegOnes int equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N"> </param>
		/// <param name="numOnes"> </param>
		/// <param name="numNegOnes"> </param>
		/// <returns> an array of integers </returns>
		public static int[] generateRandomTernary(int N, int numOnes, int numNegOnes, SecureRandom random) {
			int? one      = 1;
			int? minusOne = -1;
			int? zero     = 0;

			List<int?> list = new List<int?>();

			for(int i = 0; i < numOnes; i++) {
				list.Add(one);
			}

			for(int i = 0; i < numNegOnes; i++) {
				list.Add(minusOne);
			}

			while(list.Count < N) {
				list.Add(zero);
			}

			list.Shuffle(random);

			int[] arr = new int[N];

			for(int i = 0; i < N; i++) {
				arr[i] = list[i].Value;
			}

			return arr;
		}

		/// <summary>
		///     Reads a given number of bytes from an <code>InputStream</code>.
		///     If there are not enough bytes in the stream, an <code>IOException</code>
		///     is thrown.
		/// </summary>
		/// <param name="is"> </param>
		/// <param name="length"> </param>
		/// <returns> an array of length <code>length</code> </returns>
		/// <exception cref="IOException"> </exception>
		public static SafeArrayHandle readFullLength(Stream InputStream, int length) {
			SafeArrayHandle arr = ByteArray.Create(length);

			if(InputStream.Read(arr.Bytes, arr.Offset, arr.Length) != arr.Length) {
				throw new IOException("Not enough bytes to read.");
			}

			return arr;
		}

		/// <summary>
		///     Test for 64 bit architecture
		/// </summary>
		/// <returns>True if 64 bit architecture</returns>
		public static bool Is64Bit() {
			return Environment.Is64BitProcess;
		}

		/// <summary>
		///     Test for multi processor system
		/// </summary>
		/// <returns>True if processor count i more than 1</returns>
		public static bool IsMultiProcessor() {
			return Environment.ProcessorCount > 1;
		}
	}
}
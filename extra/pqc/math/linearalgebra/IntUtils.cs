using System;
using System.Diagnostics.CodeAnalysis;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {
	[SuppressMessage("ReSharper", "TailRecursiveCall")]
	public sealed class IntUtils {

		/// <summary>
		///     Default constructor (private).
		/// </summary>
		private IntUtils() {
			// empty
		}

		/// <summary>
		///     Compare two int arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the first int array </param>
		/// <param name="right"> the second int array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(int[] left, int[] right) {
			if(left.Length != right.Length) {
				return false;
			}

			bool result = true;

			for(int i = left.Length - 1; i >= 0; i--) {
				result &= left[i] == right[i];
			}

			return result;
		}

		/// <summary>
		///     Return a clone of the given int array. No null checks are performed.
		/// </summary>
		/// <param name="array"> the array to clone </param>
		/// <returns> the clone of the given array </returns>
		public static int[] clone(int[] array) {
			int[] result = new int[array.Length];
			Array.Copy(array, 0, result, 0, array.Length);

			return result;
		}

		/// <summary>
		///     Fill the given int array with the given value.
		/// </summary>
		/// <param name="array"> the array </param>
		/// <param name="value"> the value </param>
		public static void fill(int[] array, int value) {
			for(int i = array.Length - 1; i >= 0; i--) {
				array[i] = value;
			}
		}

		/// <summary>
		///     Sorts this array of integers according to the Quicksort algorithm. After
		///     calling this method this array is sorted in ascending order with the
		///     smallest integer taking position 0 in the array.
		///     <para>
		///         This implementation is based on the quicksort algorithm as described in
		///         <code>Data Structures In Java</code> by Thomas A. Standish, Chapter 10,
		///         ISBN 0-201-30564-X.
		///     </para>
		/// </summary>
		/// <param name="source"> the array of integers that needs to be sorted. </param>
		public static void quicksort(int[] source) {
			quicksort(source, 0, source.Length - 1);
		}

		/// <summary>
		///     Sort a subarray of a source array. The subarray is specified by its start
		///     and end index.
		/// </summary>
		/// <param name="source"> the int array to be sorted </param>
		/// <param name="left">   the start index of the subarray </param>
		/// <param name="right">  the end index of the subarray </param>
		public static void quicksort(int[] source, int left, int right) {
			if(right > left) {
				int index = partition(source, left, right, right);
				quicksort(source, left, index - 1);
				quicksort(source, index       + 1, right);
			}
		}

		/// <summary>
		///     Split a subarray of a source array into two partitions. The left
		///     partition contains elements that have value less than or equal to the
		///     pivot element, the right partition contains the elements that have larger
		///     value.
		/// </summary>
		/// <param name="source">     the int array whose subarray will be splitted </param>
		/// <param name="left">       the start position of the subarray </param>
		/// <param name="right">      the end position of the subarray </param>
		/// <param name="pivotIndex"> the index of the pivot element inside the array </param>
		/// <returns> the new index of the pivot element inside the array </returns>
		private static int partition(int[] source, int left, int right, int pivotIndex) {

			int pivot = source[pivotIndex];
			source[pivotIndex] = source[right];
			source[right]      = pivot;

			int index = left;

			for(int i = left; i < right; i++) {
				if(source[i] <= pivot) {
					int tmp = source[index];
					source[index] = source[i];
					source[i]     = tmp;
					index++;
				}
			}

			int tmp2 = source[index];
			source[index] = source[right];
			source[right] = tmp2;

			return index;
		}

		/// <summary>
		///     Generates a subarray of a given int array.
		/// </summary>
		/// <param name="input">
		///     -
		///     the input int array
		/// </param>
		/// <param name="start">
		///     -
		///     the start index
		/// </param>
		/// <param name="end">
		///     -
		///     the end index
		/// </param>
		/// <returns>
		///     a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
		///     <tt>end</tt>
		/// </returns>
		public static int[] subArray(int[] input, int start, int end) {
			int[] result = new int[end - start];
			Array.Copy(input, start, result, 0, end - start);

			return result;
		}

		/// <param name="input"> an int array </param>
		/// <returns> a human readable form of the given int array </returns>
		public static string ToString(int[] input) {
			string result = "";

			for(int i = 0; i < input.Length; i++) {
				result += input[i] + " ";
			}

			return result;
		}

		/// <param name="input"> an int arary </param>
		/// <returns> the int array as hex string </returns>
		public static string toHexString(int[] input) {
			return ByteUtils.toHexString(BigEndianConversions.toByteArray(input));
		}
	}

}
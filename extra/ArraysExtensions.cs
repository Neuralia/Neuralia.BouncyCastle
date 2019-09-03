using System;
using System.Text;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Allocation;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra {
	/// <summary> General array utilities.</summary>
	public abstract class ArraysExtensions {
		public static IByteArray Concatenate(IByteArray a, IByteArray b) {
			return FastArrays.Concatenate(a, b);
		}

		public static byte[] Concatenate(byte[] a, byte[] b, byte[] c) {
			if((a != null) && (b != null) && (c != null)) {
				byte[] rv = new byte[a.Length + b.Length + c.Length];

				Buffer.BlockCopy(a, 0, rv, 0, a.Length);
				Buffer.BlockCopy(b, 0, rv, a.Length, b.Length);
				Buffer.BlockCopy(c, 0, rv, a.Length + b.Length, c.Length);

				return rv;
			}

			if(a == null) {
				return Arrays.Concatenate(b, c);
			}

			if(b == null) {
				return Arrays.Concatenate(a, c);
			}

			return Arrays.Concatenate(a, b);
		}

		public static IByteArray Concatenate(IByteArray a, IByteArray b, IByteArray c) {
			if((a != null) && (b != null) && (c != null)) {
				IByteArray rv = MemoryAllocators.Instance.cryptoAllocator.Take(a.Length + b.Length + c.Length);

				a.CopyTo(rv, 0, 0, a.Length);
				b.CopyTo(rv, 0, a.Length, b.Length);
				c.CopyTo(rv, 0, a.Length + b.Length, c.Length);

				return rv;
			}

			if(a == null) {
				return Concatenate(b, c);
			}

			if(b == null) {
				return Concatenate(a, c);
			}

			return Concatenate(a, b);
		}

		public static IByteArray WrapMemory(byte[] array) {
			IByteArray rv = MemoryAllocators.Instance.cryptoAllocator.Take(array.Length);
			rv.CopyFrom((ReadOnlySpan<byte>) array, 0, 0, array.Length);

			return rv;
		}

		public static byte[] UnWrapMemory(IByteArray array) {
			//TODO: fix this, its inneficient
			byte[] entry = new byte[array.Length];
			array.CopyTo(entry, 0, 0, array.Length);

			return entry;
		}

		[CLSCompliant(false)]
		public static byte[][] Clone(byte[][] data) {
			if(data == null) {
				return null;
			}

			byte[][] copy = new byte[data.Length][];

			for(int i = 0; i != copy.Length; i++) {
				copy[i] = Arrays.Clone(data[i]);
			}

			return copy;
		}

		[CLSCompliant(false)]
		public static byte[][][] Clone(byte[][][] data) {
			if(data == null) {
				return null;
			}

			byte[][][] copy = new byte[data.Length][][];

			for(int i = 0; i != copy.Length; i++) {
				copy[i] = Clone(data[i]);
			}

			return copy;
		}

		public static void Fill(short[] array, short value) {
			for(int i = 0; i < array.Length; i++) {
				array[i] = value;
			}
		}
		
		public static void Fill(int[] array, int value) {
			for(int i = 0; i < array.Length; i++) {
				array[i] = value;
			}
		}

		public static void Fill(long[] array, long value) {
			for(int i = 0; i < array.Length; i++) {
				array[i] = value;
			}
		}

		public static void Fill(byte[] array, int start, int finish, byte value) {
			for(int i = start; i < finish; i++) {
				array[i] = value;
			}
		}

		public static void Fill(short[] array, int start, int finish, short value) {
			for(int i = start; i < finish; i++) {
				array[i] = value;
			}
		}
		
		public static T[] Clone<T>(
			T[] data)
		{
			return (T[]) data?.Clone();
		}
		
		public static BigInteger[] CopyOf(BigInteger[] data, int newLength)
		{
			BigInteger[] tmp = new BigInteger[newLength];
			Array.Copy(data, 0, tmp, 0, Math.Min(newLength, data.Length));
			return tmp;
		}
		
		public static BigInteger[] CopyOfRange(BigInteger[] data, int from, int to)
		{
			int newLength = GetLength(from, to);
			BigInteger[] tmp = new BigInteger[newLength];
			Buffer.BlockCopy(data, from, tmp, 0, Math.Min(newLength, data.Length - from));
			return tmp;
		}
		
		private static int GetLength(int from, int to)
		{
			int newLength = to - from;
			if (newLength < 0)
				throw new ArgumentException(from + " > " + to);
			return newLength;
		}
		
		public static bool AreEqual<T>(
			T[]  a,
			T[]  b) where T : class
		{
			if (a == b)
				return true;

			if (a == null || b == null)
				return false;

			return HaveSameContents(a, b);
		}
		
		private static bool HaveSameContents<T> (
			T[] a,
			T[] b) where T : class
		{
			int i = a.Length;
			if (i != b.Length)
				return false;
			while (i != 0)
			{
				--i;
				if (a[i] != b[i])
					return false;
			}
			return true;
		}
		
		public static string ToString(byte[] a)
		{
			StringBuilder sb = new StringBuilder('[');
			if (a.Length > 0)
			{
				sb.Append(a[0]);
				for (int index = 1; index < a.Length; ++index)
				{
					sb.Append(", ").Append(a[index]);
				}
			}
			sb.Append(']');
			return sb.ToString();
		}
		
		
	}
}
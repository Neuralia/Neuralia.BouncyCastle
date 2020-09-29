using System;
using System.Linq;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;

namespace Neuralia.BouncyCastle.extra {

    /// <summary>
    ///     A faster version of the default Arrays utility class
    /// </summary>
    public class FastArrays {

//	    public static unsafe bool FastCompare(byte[] a1, byte[] a2) {
//	        if(a1==a2) return true;
//	        if(a1==null || a2==null || a1.Length!=a2.Length)
//	            return false;
//	        fixed (byte* p1=a1, p2=a2) {
//	            byte* x1=p1, x2=p2;
//	            int l = a1.Length;
//	            for (int i=0; i < l/8; i++, x1+=8, x2+=8)
//	                if (*((long*)x1) != *((long*)x2)) return false;
//	            if ((l & 4)!=0) { if (*((int*)x1)!=*((int*)x2)) return false; x1+=4; x2+=4; }
//	            if ((l & 2)!=0) { if (*((short*)x1)!=*((short*)x2)) return false; x1+=2; x2+=2; }
//	            if ((l & 1)!=0) if (*((byte*)x1) != *((byte*)x2)) return false;
//	            return true;
//	        }
//	    }

        /// <summary>
        ///     Are two arrays equal.
        /// </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(byte[] a, byte[] b) {

			//return FastCompare(a,b);
			return a.SequenceEqual(b);
		}

		public static bool AreEqual(SafeArrayHandle a, SafeArrayHandle b) {

			//return FastCompare(a,b);
			return a.Equals(b);
		}

		public static int GetHashCode(byte[] data) {
			if(data == null) {
				return 0;
			}

			int i  = data.Length;
			int hc = i + 1;

			while(--i >= 0) {
				hc *= 257;
				hc ^= data[i];
			}

			return hc;
		}

		public static int GetHashCode(byte[] data, int off, int len) {
			if(data == null) {
				return 0;
			}

			int i  = len;
			int hc = i + 1;

			while(--i >= 0) {
				hc *= 257;
				hc ^= data[off + i];
			}

			return hc;
		}

		public static byte[] Clone(byte[] data) {
			return data == null ? null : (byte[]) data.Clone();
		}

		public static SafeArrayHandle Clone(SafeArrayHandle data) {
			if(data.IsNull) {
				return null;
			}

			SafeArrayHandle clone = SafeArrayHandle.Create(data.Length);
			data.Entry.CopyTo(clone.Entry, 0, 0, clone.Length);

			return clone;
		}

		[CLSCompliant(false)]
		public static ulong[] Clone(ulong[] data) {
			return data == null ? null : (ulong[]) data.Clone();
		}

		public static byte[] Concatenate(byte[] a, byte[] b) {
			if(a == null) {
				return Clone(b);
			}

			if(b == null) {
				return Clone(a);
			}

			byte[] newbuffer = new byte[a.Length + b.Length];

			Buffer.BlockCopy(a, 0, newbuffer, 0, a.Length);
			Buffer.BlockCopy(b, 0, newbuffer, a.Length, b.Length);

			return newbuffer;
		}

		public static SafeArrayHandle Concatenate(SafeArrayHandle a, SafeArrayHandle b) {
			if(a == null) {
				return Clone(b);
			}

			if(b == null) {
				return Clone(a);
			}

			SafeArrayHandle joined = SafeArrayHandle.Create(a.Length + b.Length);

			a.Entry.CopyTo(joined.Entry, 0, 0, a.Length);
			b.Entry.CopyTo(joined.Entry, 0, a.Length, b.Length);

			return joined;
		}

		public static byte[] CopyOfRange(byte[] data, int from, int to) {
			int    newLength = to - from;
			byte[] tmp       = new byte[newLength];
			Buffer.BlockCopy(data, from, tmp, 0, Math.Min(newLength, data.Length - from));

			return tmp;
		}

		public static SafeArrayHandle CopyOf(SafeArrayHandle data, int newLength) {
			SafeArrayHandle tmp = SafeArrayHandle.Create(newLength);

			tmp.Entry.CopyFrom(data.Entry, 0, 0, Math.Min(newLength, data.Length));

			return tmp;
		}
		
		/// <summary>
		/// A constant time equals comparison - does not terminate early if
		/// test will fail.
		/// </summary>
		/// <param name="a">first array</param>
		/// <param name="b">second array</param>
		/// <returns>true if arrays equal, false otherwise.</returns>
		public static bool ConstantTimeAreEqual(
			SafeArrayHandle	a,
			SafeArrayHandle	b)
		{
			int i = a.Length;
			if (i != b.Length)
				return false;
			int cmp = 0;
			while (i != 0)
			{
				--i;
				cmp |= (a[i] ^ b[i]);
			}
			return cmp == 0;
		}
	}
}
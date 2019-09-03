using Org.BouncyCastle.Crypto.Utilities;

namespace Neuralia.BouncyCastle.extra.crypto.Utilities {
	/// <summary>
	///     external access to internal Pack
	/// </summary>
	public sealed class Pack2 {
		private Pack2() {
		}

		public static void UInt16_To_BE(ushort n, byte[] bs) {
			Pack.UInt16_To_BE(n, bs);
		}

		public static void UInt16_To_BE(ushort n, byte[] bs, int off) {
			Pack.UInt16_To_BE(n, bs, off);
		}

		public static ushort BE_To_UInt16(byte[] bs) {
			return Pack.BE_To_UInt16(bs);
		}

		public static ushort BE_To_UInt16(byte[] bs, int off) {
			return Pack.BE_To_UInt16(bs, off);
		}

		public static byte[] UInt32_To_BE(uint n) {
			return Pack.UInt32_To_BE(n);
		}

		public static void UInt32_To_BE(uint n, byte[] bs) {
			Pack.UInt32_To_BE(n, bs);
		}

		public static void UInt32_To_BE(uint n, byte[] bs, int off) {
			Pack.UInt32_To_BE(n, bs, off);
		}

		public static byte[] UInt32_To_BE(uint[] ns) {
			return Pack.UInt32_To_BE(ns);
		}

		public static void UInt32_To_BE(uint[] ns, byte[] bs, int off) {
			Pack.UInt32_To_BE(ns, bs, off);
		}

		public static uint BE_To_UInt32(byte[] bs) {
			return Pack.BE_To_UInt32(bs);
		}

		public static uint BE_To_UInt32(byte[] bs, int off) {
			return Pack.BE_To_UInt32(bs, off);
		}

		public static void BE_To_UInt32(byte[] bs, int off, uint[] ns) {
			Pack.BE_To_UInt32(bs, off, ns);
		}

		public static byte[] UInt64_To_BE(ulong n) {
			return Pack.UInt64_To_BE(n);
		}

		public static void UInt64_To_BE(ulong n, byte[] bs) {
			Pack.UInt64_To_BE(n, bs);
		}

		public static void UInt64_To_BE(ulong n, byte[] bs, int off) {
			Pack.UInt64_To_BE(n, bs, off);
		}

		public static byte[] UInt64_To_BE(ulong[] ns) {
			return Pack.UInt64_To_BE(ns);
		}

		public static void UInt64_To_BE(ulong[] ns, byte[] bs, int off) {
			Pack.UInt64_To_BE(ns, bs, off);
		}

		public static ulong BE_To_UInt64(byte[] bs) {
			return Pack.BE_To_UInt64(bs);
		}

		public static ulong BE_To_UInt64(byte[] bs, int off) {
			return Pack.BE_To_UInt64(bs, off);
		}

		public static void BE_To_UInt64(byte[] bs, int off, ulong[] ns) {
			Pack.BE_To_UInt64(bs, off, ns);
		}

		public static void UInt16_To_LE(ushort n, byte[] bs) {
			Pack.UInt16_To_LE(n, bs);
		}

		public static void UInt16_To_LE(ushort n, byte[] bs, int off) {
			Pack.UInt16_To_LE(n, bs, off);
		}

		public static ushort LE_To_UInt16(byte[] bs) {
			return Pack.LE_To_UInt16(bs);
		}

		public static ushort LE_To_UInt16(byte[] bs, int off) {
			return Pack.LE_To_UInt16(bs, off);
		}

		public static byte[] UInt32_To_LE(uint n) {
			return Pack.UInt32_To_LE(n);
		}

		public static void UInt32_To_LE(uint n, byte[] bs) {
			Pack.UInt32_To_LE(n, bs);
		}

		public static void UInt32_To_LE(uint n, byte[] bs, int off) {
			Pack.UInt32_To_LE(n, bs, off);
		}

		public static byte[] UInt32_To_LE(uint[] ns) {
			return Pack.UInt32_To_LE(ns);
		}

		public static void UInt32_To_LE(uint[] ns, byte[] bs, int off) {
			Pack.UInt32_To_LE(ns, bs, off);
		}

		public static uint LE_To_UInt32(byte[] bs) {
			return Pack.LE_To_UInt32(bs);
		}

		public static uint LE_To_UInt32(byte[] bs, int off) {
			return Pack.LE_To_UInt32(bs, off);
		}

		public static void LE_To_UInt32(byte[] bs, int off, uint[] ns) {
			Pack.LE_To_UInt32(bs, off, ns);
		}

		public static void LE_To_UInt32(byte[] bs, int bOff, uint[] ns, int nOff, int count) {
			Pack.LE_To_UInt32(bs, bOff, ns, nOff, count);
		}

		public static uint[] LE_To_UInt32(byte[] bs, int off, int count) {
			return Pack.LE_To_UInt32(bs, off, count);
		}

		public static byte[] UInt64_To_LE(ulong n) {
			return Pack.UInt64_To_LE(n);
		}

		public static void UInt64_To_LE(ulong n, byte[] bs) {
			Pack.UInt64_To_LE(n, bs);
		}

		public static void UInt64_To_LE(ulong n, byte[] bs, int off) {
			Pack.UInt64_To_LE(n, bs, off);
		}

		public static byte[] UInt64_To_LE(ulong[] ns) {
			return Pack.UInt64_To_LE(ns);
		}

		public static void UInt64_To_LE(ulong[] ns, byte[] bs, int off) {
			Pack.UInt64_To_LE(ns, bs, off);
		}

		public static void UInt64_To_LE(ulong[] ns, int nsOff, int nsLen, byte[] bs, int bsOff) {
			Pack.UInt64_To_LE(ns, nsOff, nsLen, bs, bsOff);
		}

		public static ulong LE_To_UInt64(byte[] bs) {
			return Pack.LE_To_UInt64(bs);
		}

		public static ulong LE_To_UInt64(byte[] bs, int off) {
			return Pack.LE_To_UInt64(bs, off);
		}

		public static void LE_To_UInt64(byte[] bs, int off, ulong[] ns) {
			Pack.LE_To_UInt64(bs, off, ns);
		}

		public static void LE_To_UInt64(byte[] bs, int bsOff, ulong[] ns, int nsOff, int nsLen) {
			Pack.LE_To_UInt64(bs, bsOff, ns, nsOff, nsLen);
		}
	}
}
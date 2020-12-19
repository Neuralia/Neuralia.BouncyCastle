using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.pqc.crypto.ntru.numeric;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	/// <summary>
	/// Provides methods for CCA2-Secure Conversions of McEliece PKCS
	/// </summary>
	internal sealed class Conversions
	{
		private static readonly BigInteger ZERO = BigInteger.ValueOf(0);
		private static readonly BigInteger ONE = BigInteger.ValueOf(1);

		/// <summary>
		/// Default constructor (private).
		/// </summary>
		private Conversions()
		{
		}

		/// <summary>
		/// Encode a number between 0 and (n|t) (binomial coefficient) into a binary
		/// vector of length n with weight t. The number is given as a byte array.
		/// Only the first s bits are used, where s = floor[log(n|t)].
		/// </summary>
		/// <param name="n"> integer </param>
		/// <param name="t"> integer </param>
		/// <param name="m"> the message as a byte array </param>
		/// <returns> the encoded message as <seealso cref="GF2Vector"/> </returns>


		public static GF2Vector encode(int n, int t, SafeArrayHandle m)
		{
			if (n < t)
			{
				throw new ArgumentException("n < t");
			}

			// compute the binomial c = (n|t)
			BigInteger c = IntegerFunctions.binomial(n, t);
			// get the number encoded in m
			BigInteger i = new BigInteger(1, m);
			// compare
			if (i.CompareTo(c) >= 0)
			{
				throw new ArgumentException("Encoded number too large.");
			}

			GF2Vector result = new GF2Vector(n);

			int nn = n;
			int tt = t;
			for (int j = 0; j < n; j++)
			{
				c = c.Multiply(BigInteger.ValueOf(nn - tt)).Divide(
					BigInteger.ValueOf(nn));
				nn--;
				if (c.CompareTo(i) <= 0)
				{
					result.Bit = j;
					i = i - c;
					tt--;
					if (nn == tt)
					{
						c = ONE;
					}
					else
					{
						c = (c.Multiply(BigInteger.ValueOf(tt + 1)))
							.Divide(BigInteger.ValueOf(nn - tt));
					}
				}
			}

			return result;
		}

		/// <summary>
		/// Decode a binary vector of length n and weight t into a number between 0
		/// and (n|t) (binomial coefficient). The result is given as a byte array of
		/// length floor[(s+7)/8], where s = floor[log(n|t)].
		/// </summary>
		/// <param name="n">   integer </param>
		/// <param name="t">   integer </param>
		/// <param name="vec"> the binary vector </param>
		/// <returns> the decoded vector as a byte array </returns>
		public static SafeArrayHandle decode(int n, int t, GF2Vector vec)
		{
			if ((vec.Length != n) || (vec.HammingWeight != t))
			{
				throw new ArgumentException("vector has wrong length or hamming weight");
			}
			int[] vecArray = vec.VecArray;

			BigInteger bc = IntegerFunctions.binomial(n, t);
			BigInteger d = ZERO;
			int nn = n;
			int tt = t;
			for (int i = 0; i < n; i++)
			{
				bc = bc.Multiply(BigInteger.ValueOf(nn - tt)).Divide(BigInteger.ValueOf(nn));
				nn--;

				int q = i >> 5;
				int e = vecArray[q] & (1 << (i & 0x1f));
				if (e != 0)
				{
					d = d + bc;
					tt--;
					if (nn == tt)
					{
						bc = ONE;
					}
					else
					{
						bc = bc.Multiply(BigInteger.ValueOf(tt + 1)).Divide(BigInteger.ValueOf(nn - tt));
					}

				}
			}

			return BigIntUtils.toMinimalByteArray(d);
		}

		/// <summary>
		/// Compute a message representative of a message given as a vector of length
		/// <tt>n</tt> bit and of hamming weight <tt>t</tt>. The result is a
		/// byte array of length <tt>(s+7)/8</tt>, where
		/// <tt>s = floor[log(n|t)]</tt>.
		/// </summary>
		/// <param name="n"> integer </param>
		/// <param name="t"> integer </param>
		/// <param name="m"> the message vector as a byte array </param>
		/// <returns> a message representative for <tt>m</tt> </returns>
		public static SafeArrayHandle signConversion(int n, int t, SafeArrayHandle m)
		{
			if (n < t)
			{
				throw new ArgumentException("n < t");
			}

			BigInteger bc = IntegerFunctions.binomial(n, t);
			// finds s = floor[log(binomial(n,t))]
			int s = bc.BitLength - 1;
			// s = sq*8 + sr;
			int sq = s >> 3;
			int sr = s & 7;
			if (sr == 0)
			{
				sq--;
				sr = 8;
			}

			// n = nq*8+nr;
			int nq = n >> 3;
			int nr = n & 7;
			if (nr == 0)
			{
				nq--;
				nr = 8;
			}
			// take s bit from m
			SafeArrayHandle data = SafeArrayHandle.Create(nq + 1);
			if (m.Length < data.Length)
			{
				m.Entry.CopyTo(data.Entry);
				for (int i = m.Length; i < data.Length; i++)
				{
					data[i] = 0;
				}
			}
			else
			{
				m.Entry.CopyTo(data.Entry,0,0,nq);
				int h = (1 << nr) - 1;
				data[nq] = (byte)(h & m[nq]);
			}

			BigInteger d = ZERO;
			int nn = n;
			int tt = t;
			for (int i = 0; i < n; i++)
			{
				bc = (bc.Multiply(new BigInteger(Convert.ToString(nn - tt)))).Divide(new BigInteger(Convert.ToString(nn)));
				nn--;

				int q = (int)((uint)i >> 3);
				int r = i & 7;
				r = 1 << r;
				byte e = (byte)(r & data[q]);
				if (e != 0)
				{
					d = d + bc;
					tt--;
					if (nn == tt)
					{
						bc = ONE;
					}
					else
					{
						bc = (bc.Multiply(new BigInteger(Convert.ToString(tt + 1)))).Divide(new BigInteger(Convert.ToString(nn - tt)));

					}
				}
			}

			SafeArrayHandle result = SafeArrayHandle.Create(sq + 1);
			SafeArrayHandle help = d.ToByteArray();
			if (help.Length < result.Length)
			{
				help.Entry.CopyTo(result.Entry);
				for (int i = help.Length; i < result.Length; i++)
				{
					result[i] = 0;
				}
			}
			else
			{
				help.Entry.CopyTo(result.Entry,0,0,sq);
				result[sq] = (byte)(((1 << sr) - 1) & help[sq]);
			}

			return result;
		}

	}

}
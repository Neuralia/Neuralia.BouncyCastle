using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;
using Org.BouncyCastle.Crypto;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	public class McElieceParameters : ICipherParameters
	{

		/// <summary>
		/// The default extension degree
		/// </summary>
		public const int DEFAULT_M = 11;

		/// <summary>
		/// The default error correcting capability.
		/// </summary>
		public const int DEFAULT_T = 50;

		/// <summary>
		/// extension degree of the finite field GF(2^m)
		/// </summary>
		private int m;

		/// <summary>
		/// error correction capability of the code
		/// </summary>
		private int t;

		/// <summary>
		/// length of the code
		/// </summary>
		private int n;
		
		private readonly int k;

		/// <summary>
		/// the field polynomial
		/// </summary>
		private int fieldPoly;

		private IDigest digest;

		/// <summary>
		/// Constructor. Set the default parameters: extension degree.
		/// </summary>
		public McElieceParameters() : this(DEFAULT_M, DEFAULT_T)
		{
		}

		public McElieceParameters(IDigest digest) : this(DEFAULT_M, DEFAULT_T, digest)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="keysize"> the length of a Goppa code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>keysize &lt; 1</tt>. </exception>
		public McElieceParameters(int keysize) : this(keysize, null)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="keysize"> the length of a Goppa code </param>
		/// <param name="digest"> CCA2 mode digest </param>
		/// <exception cref="IllegalArgumentException"> if <tt>keysize &lt; 1</tt>. </exception>
		public McElieceParameters(int keysize, IDigest digest)
		{
			if (keysize < 1)
			{
				throw new System.ArgumentException("key size must be positive");
			}

			this.m = 0;
			this.n = 1;
			while (this.n < keysize)
			{
				this.n <<= 1;
				this.m++;
			}

			this.t = (int)((uint) this.n >> 1);
			this.t /= this.m;
			this.k = this.n - this.m * this.t;
			this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.m);
			this.digest = digest;
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m"> degree of the finite field GF(2^m) </param>
		/// <param name="t"> error correction capability of the code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>. </exception>
		public McElieceParameters(int m, int t) : this(m, t, null)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m"> degree of the finite field GF(2^m) </param>
		/// <param name="t"> error correction capability of the code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>. </exception>
		public McElieceParameters(int m, int t, IDigest digest)
		{
			if (m < 1)
			{
				throw new System.ArgumentException("m must be positive");
			}
			if (m > 32)
			{
				throw new System.ArgumentException("m is too large");
			}
			this.m = m;
			this.n = 1 << m;
			if (t < 0)
			{
				throw new System.ArgumentException("t must be positive");
			}
			if (t > this.n)
			{
				throw new System.ArgumentException("t must be less than n = 2^m");
			}

			this.k = this.n - m * t;
			this.t = t;
			this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
			this.digest = digest;
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m">    degree of the finite field GF(2^m) </param>
		/// <param name="t">    error correction capability of the code </param>
		/// <param name="poly"> the field polynomial </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
		/// <tt>poly</tt> is not an irreducible field polynomial. </exception>
		public McElieceParameters(int m, int t, int poly) : this(m, t, poly, null)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m">    degree of the finite field GF(2^m) </param>
		/// <param name="t">    error correction capability of the code </param>
		/// <param name="poly"> the field polynomial </param>
		/// <param name="digest"> CCA2 mode digest </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
		/// <tt>poly</tt> is not an irreducible field polynomial. </exception>
		public McElieceParameters(int m, int t, int poly, IDigest digest)
		{
			this.m = m;
			if (m < 1)
			{
				throw new System.ArgumentException("m must be positive");
			}
			if (m > 32)
			{
				throw new System.ArgumentException(" m is too large");
			}
			this.n = 1 << m;
			this.t = t;
			if (t < 0)
			{
				throw new System.ArgumentException("t must be positive");
			}
			if (t > this.n)
			{
				throw new System.ArgumentException("t must be less than n = 2^m");
			}
			if ((PolynomialRingGF2.degree(poly) == m) && (PolynomialRingGF2.isIrreducible(poly)))
			{
				this.fieldPoly = poly;
			}
			else
			{
				throw new System.ArgumentException("polynomial is not a field polynomial for GF(2^m)");
			}
			this.digest = digest;
		}

		/// <returns> the extension degree of the finite field GF(2^m) </returns>
		public virtual int M
		{
			get
			{
				return this.m;
			}
		}

		/// <returns> the length of the code </returns>
		public virtual int N
		{
			get
			{
				return this.n;
			}
		}

		/// <returns> the error correction capability of the code </returns>
		public virtual int T
		{
			get
			{
				return this.t;
			}
		}
		
		public virtual int K
		{
			get
			{
				return this.k;
			}
		}

		/// <returns> the field polynomial </returns>
		public virtual int FieldPoly
		{
			get
			{
				return this.fieldPoly;
			}
		}
	}

}
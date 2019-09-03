namespace org.bouncycastle.pqc.crypto.mceliece
{
	public class McElieceCCA2Parameters : McElieceParameters
	{
		private readonly string digest;

		/// <summary>
		/// Constructor. Set the default parameters: extension degree.
		/// </summary>
		public McElieceCCA2Parameters() : this(DEFAULT_M, DEFAULT_T, "SHA-256")
		{
		}

		public McElieceCCA2Parameters(string digest) : this(DEFAULT_M, DEFAULT_T, digest)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="keysize"> the length of a Goppa code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>keysize &lt; 1</tt>. </exception>
		public McElieceCCA2Parameters(int keysize) : this(keysize, "SHA-256")
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="keysize"> the length of a Goppa code </param>
		/// <param name="digest"> CCA2 mode digest </param>
		/// <exception cref="IllegalArgumentException"> if <tt>keysize &lt; 1</tt>. </exception>
		public McElieceCCA2Parameters(int keysize, string digest) : base(keysize)
		{
			this.digest = digest;
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m"> degree of the finite field GF(2^m) </param>
		/// <param name="t"> error correction capability of the code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>. </exception>
		public McElieceCCA2Parameters(int m, int t) : this(m, t, "SHA-256")
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="m"> degree of the finite field GF(2^m) </param>
		/// <param name="t"> error correction capability of the code </param>
		/// <exception cref="IllegalArgumentException"> if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
		/// <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>. </exception>
		public McElieceCCA2Parameters(int m, int t, string digest) : base(m, t)
		{
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
		public McElieceCCA2Parameters(int m, int t, int poly) : this(m, t, poly, "SHA-256")
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
		public McElieceCCA2Parameters(int m, int t, int poly, string digest) : base(m, t, poly)
		{
			this.digest = digest;
		}

		/// <summary>
		/// Return the CCA2 mode digest if set.
		/// </summary>
		/// <returns> the CCA2 digest to use, null if not present. </returns>
		public virtual string Digest
		{
			get
			{
				return this.digest;
			}
		}
	}

}
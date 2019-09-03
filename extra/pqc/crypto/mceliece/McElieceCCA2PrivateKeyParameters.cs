using Neuralia.Blockchains.Tools.Serialization;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	/// 
	/// 
	/// 
	public class McElieceCCA2PrivateKeyParameters : McElieceCCA2KeyParameters
	{
		// the length of the code
		private int n;

		// the dimension of the code
		private int k;

		// the finte field GF(2^m)
		private GF2mField field;

		// the irreducible Goppa polynomial
		private PolynomialGF2mSmallM goppaPoly;

		// the permutation
		private Permutation p;

		// the canonical check matrix
		private GF2Matrix h;

		// the matrix used to compute square roots in (GF(2^m))^t
		private PolynomialGF2mSmallM[] qInv;

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">      the length of the code </param>
		/// <param name="k">      the dimension of the code </param>
		/// <param name="field">  the finite field <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="gp">     the irreducible Goppa polynomial </param>
		/// <param name="p">      the permutation </param>
		/// <param name="digest"> name of digest algorithm </param>
		public McElieceCCA2PrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, Permutation p, string digest) : this(n, k, field, gp, GoppaCode.createCanonicalCheckMatrix(field, gp), p, digest)
		{
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">                         the length of the code </param>
		/// <param name="k">                         the dimension of the code </param>
		/// <param name="field">                     the finite field <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="gp">                        the irreducible Goppa polynomial </param>
		/// <param name="canonicalCheckMatrix">      the canonical check matrix </param>
		/// <param name="p">                         the permutation </param>
		/// <param name="digest">                    name of digest algorithm </param>
		public McElieceCCA2PrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, GF2Matrix canonicalCheckMatrix, Permutation p, string digest) : base(true, digest)
		{

			this.n = n;
			this.k = k;
			this.field = field;
			this.goppaPoly = gp;
			this.h = canonicalCheckMatrix;
			this.p = p;

			PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

			// matrix for computing square roots in (GF(2^m))^t
			this.qInv = ring.SquareRootMatrix;
		}
		
		public McElieceCCA2PrivateKeyParameters() : base(true, null)
		{

		}

		/// <returns> the length of the code </returns>
		public virtual int N
		{
			get
			{
				return this.n;
			}
		}

		/// <returns> the dimension of the code </returns>
		public virtual int K
		{
			get
			{
				return this.k;
			}
		}

		/// <returns> the degree of the Goppa polynomial (error correcting capability) </returns>
		public virtual int T
		{
			get
			{
				return this.goppaPoly.Degree;
			}
		}

		/// <returns> the finite field </returns>
		public virtual GF2mField Field
		{
			get
			{
				return this.field;
			}
		}

		/// <returns> the irreducible Goppa polynomial </returns>
		public virtual PolynomialGF2mSmallM GoppaPoly
		{
			get
			{
				return this.goppaPoly;
			}
		}

		/// <returns> the permutation P </returns>
		public virtual Permutation P
		{
			get
			{
				return this.p;
			}
		}

		/// <returns> the canonical check matrix H </returns>
		public virtual GF2Matrix H
		{
			get
			{
				return this.h;
			}
		}

		/// <returns> the matrix used to compute square roots in <tt>(GF(2^m))^t</tt> </returns>
		public virtual PolynomialGF2mSmallM[] QInv
		{
			get
			{
				return this.qInv;
			}
		}
		
		public override void Rehydrate(IDataRehydrator rehydrator) {
			this.k = rehydrator.ReadInt();
			this.n = rehydrator.ReadInt();
			var data = rehydrator.ReadNonNullableArray();
			this.field = new GF2mField(data);
			data.Return();
			data = rehydrator.ReadNonNullableArray();
			this.goppaPoly = new PolynomialGF2mSmallM(this.field, data);
			data.Return();
			data = rehydrator.ReadNonNullableArray();
			this.p = new Permutation(data);
			data.Return();
			data = rehydrator.ReadNonNullableArray();
			this.h = new GF2Matrix(data);
			data.Return();
			
			this.Digest = rehydrator.ReadString();
			int count = rehydrator.ReadInt();
			this.qInv = new PolynomialGF2mSmallM[count];
			for (int i = 0; i < count; i++)
			{
				var datax = rehydrator.ReadNonNullableArray();
				this.qInv[i] = new PolynomialGF2mSmallM(this.field, datax);
				datax.Return();
				
			}
		}

		public override void Dehydrate(IDataDehydrator dehydrator) {
			dehydrator.Write(this.k);
			dehydrator.Write(this.n);
			dehydrator.WriteNonNullable(this.field.Encoded);
			dehydrator.WriteNonNullable(this.goppaPoly.Encoded);
			dehydrator.WriteNonNullable(this.p.Encoded);
			dehydrator.WriteNonNullable(this.h.Encoded);
			dehydrator.Write(this.Digest);

			dehydrator.Write(this.qInv.Length);

			foreach(var qinvEntry in this.qInv) {
				dehydrator.WriteNonNullable(qinvEntry.Encoded);
			}
			
			
		}
	}

}
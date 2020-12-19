using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Serialization;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	public class McEliecePrivateKeyParameters : McElieceKeyParameters
	{

		// the OID of the algorithm
		private string oid;

		// the length of the code
		private int n;

		// the dimension of the code, where <tt>k &gt;= n - mt</tt>
		private int k;

		// the underlying finite field
		private GF2mField field;

		// the irreducible Goppa polynomial
		private PolynomialGF2mSmallM goppaPoly;

		// a k x k random binary non-singular matrix
		private GF2Matrix sInv;

		// the permutation used to generate the systematic check matrix
		private Permutation p1;

		// the permutation used to compute the public generator matrix
		private Permutation p2;

		// the canonical check matrix of the code
		private GF2Matrix h;

		// the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
		private PolynomialGF2mSmallM[] qInv;

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">         the length of the code </param>
		/// <param name="k">         the dimension of the code </param>
		/// <param name="field">     the field polynomial defining the finite field
		///                  <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="gp"> the irreducible Goppa polynomial </param>
		/// <param name="p1">        the permutation used to generate the systematic check
		///                  matrix </param>
		/// <param name="p2">        the permutation used to compute the public generator
		///                  matrix </param>
		/// <param name="sInv">      the matrix <tt>S<sup>-1</sup></tt> </param>
		public McEliecePrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, Permutation p1, Permutation p2, GF2Matrix sInv) : base(true, null)
		{
			this.k = k;
			this.n = n;
			this.field = field;
			this.goppaPoly = gp;
			this.sInv = sInv;
			this.p1 = p1;
			this.p2 = p2;
			this.h = GoppaCode.createCanonicalCheckMatrix(field, gp);

			PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

			  // matrix used to compute square roots in (GF(2^m))^t
			this.qInv = ring.SquareRootMatrix;
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">            the length of the code </param>
		/// <param name="k">            the dimension of the code </param>
		/// <param name="encField">     the encoded field polynomial defining the finite field
		///                     <tt>GF(2<sup>m</sup>)</tt> </param>
		/// <param name="encGoppaPoly"> the encoded irreducible Goppa polynomial </param>
		/// <param name="encSInv">      the encoded matrix <tt>S<sup>-1</sup></tt> </param>
		/// <param name="encP1">        the encoded permutation used to generate the systematic
		///                     check matrix </param>
		/// <param name="encP2">        the encoded permutation used to compute the public
		///                     generator matrix </param>
		/// <param name="encH">         the encoded canonical check matrix </param>
		/// <param name="encQInv">      the encoded matrix used to compute square roots in
		///                     <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt> </param>
		public McEliecePrivateKeyParameters(int n, int k, SafeArrayHandle encField, SafeArrayHandle encGoppaPoly, SafeArrayHandle encSInv, SafeArrayHandle encP1, SafeArrayHandle encP2, SafeArrayHandle encH, SafeArrayHandle[] encQInv) : base(true, null)
		{
			this.n = n;
			this.k = k;
			this.field = new GF2mField(encField);
			this.goppaPoly = new PolynomialGF2mSmallM(this.field, encGoppaPoly);
			this.sInv = new GF2Matrix(encSInv);
			this.p1 = new Permutation(encP1);
			this.p2 = new Permutation(encP2);
			this.h = new GF2Matrix(encH);
			this.qInv = new PolynomialGF2mSmallM[encQInv.Length];
			for (int i = 0; i < encQInv.Length; i++)
			{
				this.qInv[i] = new PolynomialGF2mSmallM(this.field, encQInv[i]);
			}
		}
		
		public McEliecePrivateKeyParameters() : base(true, null)
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

		/// <returns> the finite field <tt>GF(2<sup>m</sup>)</tt> </returns>
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

		/// <returns> the k x k random binary non-singular matrix S^-1 </returns>
		public virtual GF2Matrix SInv
		{
			get
			{
				return this.sInv;
			}
		}

		/// <returns> the permutation used to generate the systematic check matrix </returns>
		public virtual Permutation P1
		{
			get
			{
				return this.p1;
			}
		}

		/// <returns> the permutation used to compute the public generator matrix </returns>
		public virtual Permutation P2
		{
			get
			{
				return this.p2;
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

		/// <returns> the matrix used to compute square roots in
		///         <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt> </returns>
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
			this.field = new GF2mField((SafeArrayHandle)rehydrator.ReadNonNullableArray());
			this.goppaPoly = new PolynomialGF2mSmallM(this.field, (SafeArrayHandle)rehydrator.ReadNonNullableArray());
			this.sInv = new GF2Matrix((SafeArrayHandle)rehydrator.ReadNonNullableArray());
			this.p1 = new Permutation((SafeArrayHandle)rehydrator.ReadNonNullableArray());
			this.p2 = new Permutation((SafeArrayHandle)rehydrator.ReadNonNullableArray());
			this.h = new GF2Matrix((SafeArrayHandle)rehydrator.ReadNonNullableArray());
			int count = rehydrator.ReadInt();
			this.qInv = new PolynomialGF2mSmallM[count];
			for (int i = 0; i < count; i++)
			{
				this.qInv[i] = new PolynomialGF2mSmallM(this.field, (SafeArrayHandle)rehydrator.ReadNonNullableArray());
			}
		}

		public override void Dehydrate(IDataDehydrator dehydrator) {
			dehydrator.Write(this.k);
			dehydrator.Write(this.n);
			dehydrator.WriteNonNullable(this.field.Encoded);
			dehydrator.WriteNonNullable(this.goppaPoly.Encoded);
			dehydrator.WriteNonNullable(this.sInv.Encoded);
			dehydrator.WriteNonNullable(this.p1.Encoded);
			dehydrator.WriteNonNullable(this.p2.Encoded);
			dehydrator.WriteNonNullable(this.h.Encoded);

			dehydrator.Write(this.qInv.Length);

			foreach(var qinvEntry in this.qInv) {
				dehydrator.WriteNonNullable(qinvEntry.Encoded);
			}
			
			
		}
	}

}
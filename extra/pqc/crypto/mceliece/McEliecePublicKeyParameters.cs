using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Serialization;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	public class McEliecePublicKeyParameters : McElieceKeyParameters
	{
		// the length of the code
		private int n;

		// the error correction capability of the code
		private int t;

		// the generator matrix
		private GF2Matrix g;

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="n">      the length of the code </param>
		/// <param name="t">      the error correction capability of the code </param>
		/// <param name="g">      the generator matrix </param>
		public McEliecePublicKeyParameters(int n, int t, GF2Matrix g) : base(false, null)
		{
			this.n = n;
			this.t = t;
			this.g = new GF2Matrix(g);
		}

		public McEliecePublicKeyParameters() : base(false, null)
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

		/// <returns> the error correction capability of the code </returns>
		public virtual int T
		{
			get
			{
				return this.t;
			}
		}

		/// <returns> the generator matrix </returns>
		public virtual GF2Matrix G
		{
			get
			{
				return this.g;
			}
		}

		/// <returns> the dimension of the code </returns>
		public virtual int K
		{
			get
			{
				return this.g.NumRows;
			}
		}

		public override void Rehydrate(IDataRehydrator rehydrator) {
			this.n = rehydrator.ReadInt();
			this.t = rehydrator.ReadInt();
			this.g = new GF2Matrix((SafeArrayHandle)rehydrator.ReadNonNullableArray());
		}

		public override void Dehydrate(IDataDehydrator dehydrator) {
			dehydrator.Write(this.n);
			dehydrator.Write(this.t);
			dehydrator.WriteNonNullable(this.G.Encoded);
		}
	}

}
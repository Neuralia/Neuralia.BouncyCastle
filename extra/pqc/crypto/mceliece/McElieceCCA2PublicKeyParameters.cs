using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Serialization;
using Neuralia.BouncyCastle.extra.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	/// 
	/// 
	/// 
	public class McElieceCCA2PublicKeyParameters : McElieceCCA2KeyParameters
	{
		// the length of the code
		private int n;

		// the error correction capability of the code
		private int t;

		// the generator matrix
		private GF2Matrix matrixG;

		/// <summary>
		/// Constructor. </summary>
		///  <param name="n">      length of the code </param>
		/// <param name="t">      error correction capability </param>
		/// <param name="matrix"> generator matrix </param>
		/// <param name="digest"> McElieceCCA2Parameters </param>
		public McElieceCCA2PublicKeyParameters(int n, int t, GF2Matrix matrix, string digest) : base(false, digest)
		{

			this.n = n;
			this.t = t;
			this.matrixG = new GF2Matrix(matrix);
		}
		
		public McElieceCCA2PublicKeyParameters() : base(false, null)
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
				return this.matrixG;
			}
		}

		/// <returns> the dimension of the code </returns>
		public virtual int K
		{
			get
			{
				return this.matrixG.NumRows;
			}
		}
		
		public override void Rehydrate(IDataRehydrator rehydrator) {
			this.n = rehydrator.ReadInt();
			this.t = rehydrator.ReadInt();
			this.Digest = rehydrator.ReadString();
			using var data = (SafeArrayHandle)rehydrator.ReadNonNullableArray();
			this.matrixG = new GF2Matrix(data);
		}

		public override void Dehydrate(IDataDehydrator dehydrator) {
			dehydrator.Write(this.n);
			dehydrator.Write(this.t);
			dehydrator.Write(this.Digest);
			dehydrator.WriteNonNullable(this.matrixG.Encoded);
		}
	}

}
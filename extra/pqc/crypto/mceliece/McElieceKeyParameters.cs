using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Serialization;
using Org.BouncyCastle.Crypto;

namespace org.bouncycastle.pqc.crypto.mceliece
{


	public abstract class McElieceKeyParameters : AsymmetricKeyParameter, IBinarySerializable
	{
		private McElieceParameters @params;

		public McElieceKeyParameters(bool isPrivate, McElieceParameters @params) : base(isPrivate)
		{
			this.@params = @params;
		}


		public virtual McElieceParameters Parameters
		{
			get
			{
				return this.@params;
			}
		}

		public abstract void Rehydrate(IDataRehydrator rehydrator);
		public abstract void Dehydrate(IDataDehydrator dehydrator);
	}

}
using Neuralia.Blockchains.Tools.Serialization;
using Org.BouncyCastle.Crypto;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	public abstract class McElieceCCA2KeyParameters : AsymmetricKeyParameter
	{

		public McElieceCCA2KeyParameters(bool isPrivate, string digest) : base(isPrivate)
		{
			this.Digest = digest;
		}


		public virtual string Digest { get; protected set; }

		public abstract void Rehydrate(IDataRehydrator rehydrator);
		public abstract void Dehydrate(IDataDehydrator dehydrator);
	}

}
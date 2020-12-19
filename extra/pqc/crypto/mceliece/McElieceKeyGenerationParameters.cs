using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	
	public class McElieceKeyGenerationParameters : KeyGenerationParameters
	{
		private McElieceParameters @params;

		public McElieceKeyGenerationParameters(SecureRandom random, McElieceParameters @params) : base(random, 256)
		{
			// XXX key size?
			this.@params = @params;
		}

		public virtual McElieceParameters Parameters
		{
			get
			{
				return this.@params;
			}
		}
	}

}
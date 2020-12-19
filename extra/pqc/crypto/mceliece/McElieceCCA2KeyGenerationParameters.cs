using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	public class McElieceCCA2KeyGenerationParameters : KeyGenerationParameters
	{
		private McElieceCCA2Parameters @params;

		public McElieceCCA2KeyGenerationParameters(SecureRandom random, McElieceCCA2Parameters @params) : base(random, 128)
		{
			// XXX key size?
			this.@params = @params;
		}

		public virtual McElieceCCA2Parameters Parameters
		{
			get
			{
				return this.@params;
			}
		}
	}

}
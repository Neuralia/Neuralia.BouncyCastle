
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	public class NTRUEncryptionKeyParameters : AsymmetricKeyParameter {
		protected internal readonly NTRUEncryptionParameters @params;

		public NTRUEncryptionKeyParameters(bool privateKey, NTRUEncryptionParameters @params) : base(privateKey) {
			this.@params = @params;
		}

		public virtual NTRUEncryptionParameters Parameters => this.@params;
	}

}
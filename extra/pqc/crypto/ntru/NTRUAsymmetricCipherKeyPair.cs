
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {
	public class NTRUAsymmetricCipherKeyPair : AsymmetricCipherKeyPair {

		public NTRUAsymmetricCipherKeyPair(NTRUEncryptionPublicKeyParameters publicParameter, NTRUEncryptionPrivateKeyParameters privateParameter) : base(publicParameter, privateParameter) {
		}

		public new NTRUEncryptionPublicKeyParameters  Public  => (NTRUEncryptionPublicKeyParameters) base.Public;
		public new NTRUEncryptionPrivateKeyParameters Private => (NTRUEncryptionPrivateKeyParameters) base.Private;
	}
}
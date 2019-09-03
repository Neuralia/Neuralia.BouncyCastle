using Org.BouncyCastle.Crypto;

namespace org.bouncycastle.pqc.crypto.mceliece {
	public class McElieceCCA2AsymmetricCipherKeyPair : AsymmetricCipherKeyPair {

		public McElieceCCA2AsymmetricCipherKeyPair(McElieceCCA2PublicKeyParameters publicParameter, McElieceCCA2PrivateKeyParameters privateParameter) : base(publicParameter, privateParameter) {
		}

		public new McElieceCCA2PublicKeyParameters Public => (McElieceCCA2PublicKeyParameters)base.Public;
		public new McElieceCCA2PrivateKeyParameters Private => (McElieceCCA2PrivateKeyParameters)base.Private;
	}
}
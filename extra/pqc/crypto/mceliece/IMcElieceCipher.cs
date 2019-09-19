using Neuralia.Blockchains.Tools.Data;
using Org.BouncyCastle.Crypto;

namespace org.bouncycastle.pqc.crypto.mceliece {
	public interface IMcElieceCipher {
		void init(bool forEncryption, ICipherParameters param);
		SafeArrayHandle messageEncrypt(SafeArrayHandle input);
		SafeArrayHandle messageDecrypt(SafeArrayHandle input);
	}
}
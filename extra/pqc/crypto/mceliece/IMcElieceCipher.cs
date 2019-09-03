using Neuralia.Blockchains.Tools.Data;
using Org.BouncyCastle.Crypto;

namespace org.bouncycastle.pqc.crypto.mceliece {
	public interface IMcElieceCipher {
		void init(bool forEncryption, ICipherParameters param);
		IByteArray messageEncrypt(IByteArray input);
		IByteArray messageDecrypt(IByteArray input);
	}
}
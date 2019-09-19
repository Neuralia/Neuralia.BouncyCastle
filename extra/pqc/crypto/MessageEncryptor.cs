
using Neuralia.Blockchains.Tools.Data;
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto {

	/// <summary>
	///     Base interface for a PQC encryption algorithm.
	/// </summary>
	public interface MessageEncryptor {

		/// <param name="forEncrypting">
		///     true if we are encrypting a signature, false
		///     otherwise.
		/// </param>
		/// <param name="param"> key parameters for encryption or decryption. </param>
		void init(bool forEncrypting, ICipherParameters param);

		/// <param name="message"> the message to be signed. </param>
		SafeArrayHandle messageEncrypt(SafeArrayHandle message);

		/// <param name="cipher"> the cipher text of the message </param>
		/// <exception cref="InvalidCipherTextException"> </exception>
		SafeArrayHandle messageDecrypt(SafeArrayHandle cipher);
	}

}
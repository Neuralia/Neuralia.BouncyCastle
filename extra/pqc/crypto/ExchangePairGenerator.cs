
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto {

	/// <summary>
	///     Interface for NewHope style key material exchange generators.
	/// </summary>
	public interface ExchangePairGenerator {
		/// <summary>
		///     Generate an exchange pair based on the sender public key.
		/// </summary>
		/// <param name="senderPublicKey"> the public key of the exchange initiator. </param>
		/// <returns> An ExchangePair derived from the sender public key. </returns>
		/// @deprecated use generateExchange
		ExchangePair GenerateExchange(AsymmetricKeyParameter senderPublicKey);

		/// <summary>
		///     Generate an exchange pair based on the sender public key.
		/// </summary>
		/// <param name="senderPublicKey"> the public key of the exchange initiator. </param>
		/// <returns> An ExchangePair derived from the sender public key. </returns>
		ExchangePair generateExchange(AsymmetricKeyParameter senderPublicKey);
	}

}
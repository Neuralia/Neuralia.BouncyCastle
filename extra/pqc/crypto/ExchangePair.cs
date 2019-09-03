

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto {

	/// <summary>
	///     Pair for a value exchange algorithm where the responding party has no private key, such as NewHope.
	/// </summary>
	public class ExchangePair {
		private readonly byte[] shared;

		/// <summary>
		///     Base constructor.
		/// </summary>
		/// <param name="publicKey"> The responding party's public key. </param>
		/// <param name="shared"> the calculated shared value. </param>
		public ExchangePair(AsymmetricKeyParameter publicKey, byte[] shared) {
			this.PublicKey = publicKey;
			this.shared    = Arrays.Clone(shared);
		}

		/// <summary>
		///     Return the responding party's public key.
		/// </summary>
		/// <returns> the public key calculated for the exchange. </returns>
		public virtual AsymmetricKeyParameter PublicKey { get; }

		/// <summary>
		///     Return the shared value calculated with public key.
		/// </summary>
		/// <returns> the shared value. </returns>
		public virtual byte[] SharedValue => Arrays.Clone(this.shared);
	}

}
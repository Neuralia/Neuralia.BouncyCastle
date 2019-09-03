
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto {

	/// <summary>
	///     Implements the sign and verify functions for a Signature Scheme using a hash function to allow processing of large
	///     messages.
	///     <para>
	///         This class can be used with algorithms where the state associated with the private key changes as each
	///         signature is
	///         generated. Calling getUpdatedPrivateKey() will recover the private key that can be used to initialize a signer
	///         next time around.
	///     </para>
	/// </summary>
	public class DigestingStateAwareMessageSigner : DigestingMessageSigner {
		private readonly StateAwareMessageSigner signer;

		public DigestingStateAwareMessageSigner(StateAwareMessageSigner messSigner, IDigest messDigest) : base(messSigner, messDigest) {

			this.signer = messSigner;
		}

		/// <summary>
		///     Return the current version of the private key with the updated state.
		///     <para>
		///         <b>Note:</b> calling this method will effectively disable the Signer from being used for further
		///         signature generation without another call to init().
		///     </para>
		/// </summary>
		/// <returns> an updated private key object, which can be used for later signature generation. </returns>
		public virtual AsymmetricKeyParameter UpdatedPrivateKey => this.signer.UpdatedPrivateKey;
	}

}
using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {

	/// <summary>
	///     Signer for the qTESLA algorithm (https://qtesla.org/)
	/// </summary>
	public class QTESLASigner : IMessageSigner {

		/// <summary>
		///     The Private Key of the Identity Whose Signature Will be Generated
		/// </summary>
		private QTESLAPrivateKeyParameters privateKey;

		/// <summary>
		///     The Public Key of the Identity Whose Signature Will be Generated
		/// </summary>
		private QTESLAPublicKeyParameters publicKey;

		/// <summary>
		///     The Source of Randomness for private key operations
		/// </summary>
		private SecureRandom secureRandom;

		/// <summary>
		///     Initialise the signer.
		/// </summary>
		/// <param name="forSigning">
		///     true if we are generating a signature, false
		///     otherwise.
		/// </param>
		/// <param name="param">      ParametersWithRandom containing a private key for signature generation, public key otherwise. </param>
		public virtual void init(bool forSigning, ICipherParameters param) {
			if(forSigning) {
				if(param is ParametersWithRandom) {
					this.secureRandom = ((ParametersWithRandom) param).Random;
					this.privateKey   = (QTESLAPrivateKeyParameters) ((ParametersWithRandom) param).Parameters;
				} else {
					this.secureRandom = new SecureRandom();
					this.privateKey   = (QTESLAPrivateKeyParameters) param;
				}

				this.publicKey = null;
				QTESLASecurityCategory.validate(this.privateKey.SecurityCategory);
			} else {
				this.privateKey = null;
				this.publicKey  = (QTESLAPublicKeyParameters) param;
				QTESLASecurityCategory.validate(this.publicKey.SecurityCategory);
			}
		}

		/// <summary>
		///     Generate a signature directly for the passed in message.
		/// </summary>
		/// <param name="message"> the message to be signed. </param>
		/// <returns> the signature generated. </returns>
		public virtual byte[] generateSignature(byte[] message) {
			sbyte[] sig = new sbyte[QTESLASecurityCategory.getSignatureSize(this.privateKey.SecurityCategory)];

			switch(this.privateKey.SecurityCategory) {
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_I:
					QTESLA.signingI(sig, (sbyte[]) (Array) message, 0, message.Length, this.privateKey.Secret, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_III:
					QTESLA.signingIII(sig, (sbyte[]) (Array) message, 0, message.Length, this.privateKey.Secret, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_V:
					QTESLA.signingV(sig, (sbyte[]) (Array) message, 0, message.Length, this.privateKey.Secret, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.PROVABLY_SECURE_I:
					QTESLA.signingIP(sig, (sbyte[]) (Array) message, 0, message.Length, this.privateKey.Secret, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.PROVABLY_SECURE_III:
					QTESLA.signingIIIP(sig, (sbyte[]) (Array) message, 0, message.Length, this.privateKey.Secret, this.secureRandom);

					break;
				default:

					throw new ArgumentException("unknown security category: " + this.privateKey.SecurityCategory);
			}

			return (byte[]) (Array) sig;
		}

		/// <summary>
		///     Verify the signature against the passed in message.
		/// </summary>
		/// <param name="message"> the message that was supposed to have been signed. </param>
		/// <param name="signature"> the signature of the message </param>
		/// <returns> true if the signature passes, false otherwise. </returns>
		public virtual bool verifySignature(byte[] message, byte[] signature) {
			int status;

			switch(this.publicKey.SecurityCategory) {
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_I:
					status = QTESLA.verifyingI((sbyte[]) (Array) message, (sbyte[]) (Array) signature, 0, signature.Length, this.publicKey.PublicData);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_III:
					status = QTESLA.verifyingIII((sbyte[]) (Array) message, (sbyte[]) (Array) signature, 0, signature.Length, this.publicKey.PublicData);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_V:
					status = QTESLA.verifyingV((sbyte[]) (Array) message, (sbyte[]) (Array) signature, 0, signature.Length, this.publicKey.PublicData);

					break;
				case QTESLASecurityCategory.SecurityCategories.PROVABLY_SECURE_I:
					status = QTESLA.verifyingPI((sbyte[]) (Array) message, (sbyte[]) (Array) signature, 0, signature.Length, this.publicKey.PublicData);

					break;
				case QTESLASecurityCategory.SecurityCategories.PROVABLY_SECURE_III:
					status = QTESLA.verifyingPIII((sbyte[]) (Array) message, (sbyte[]) (Array) signature, 0, signature.Length, this.publicKey.PublicData);

					break;
				default:

					throw new ArgumentException("unknown security category: " + this.publicKey.SecurityCategory);
			}

			return 0 == status;
		}
	}

}
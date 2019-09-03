using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Neuralia.BouncyCastle.extra.pqc.crypto {

	/// <summary>
	///     Implements the sign and verify functions for a Signature Scheme using a hash function to allow processing of large
	///     messages.
	/// </summary>
	public class DigestingMessageSigner : ISigner {
		private readonly IDigest        messDigest;
		private readonly IMessageSigner messSigner;
		private          bool           forSigning;

		public DigestingMessageSigner(IMessageSigner messSigner, IDigest messDigest) {
			this.messSigner = messSigner;
			this.messDigest = messDigest;
		}

		//???
		public string AlgorithmName => "Digest Message Signer";

		public virtual void Init(bool forSigning, ICipherParameters param) {

			this.forSigning = forSigning;
			AsymmetricKeyParameter k;

			if(param is ParametersWithRandom) {
				k = (AsymmetricKeyParameter) ((ParametersWithRandom) param).Parameters;
			} else {
				k = (AsymmetricKeyParameter) param;
			}

			if(forSigning && !k.IsPrivate) {
				throw new ArgumentException("Signing Requires Private Key.");
			}

			if(!forSigning && k.IsPrivate) {
				throw new ArgumentException("Verification Requires Public Key.");
			}

			this.Reset();

			this.messSigner.init(forSigning, param);
		}

		/// <summary>
		///     This function signs the message that has been updated, making use of the
		///     private key.
		/// </summary>
		/// <returns> the signature of the message. </returns>
		public virtual byte[] GenerateSignature() {
			if(!this.forSigning) {
				throw new InvalidOperationException("DigestingMessageSigner not initialised for signature generation.");
			}

			byte[] hash = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(hash, 0);

			return this.messSigner.generateSignature(hash);
		}

		public virtual void Update(byte b) {
			this.messDigest.Update(b);
		}

		public virtual void BlockUpdate(byte[] @in, int off, int len) {
			this.messDigest.BlockUpdate(@in, off, len);
		}

		public virtual void Reset() {
			this.messDigest.Reset();
		}

		/// <summary>
		///     This function verifies the signature of the message that has been
		///     updated, with the aid of the public key.
		/// </summary>
		/// <param name="signature"> the signature of the message is given as a byte array. </param>
		/// <returns> true if the signature has been verified, false otherwise. </returns>
		public virtual bool VerifySignature(byte[] signature) {
			if(this.forSigning) {
				throw new InvalidOperationException("DigestingMessageSigner not initialised for verification");
			}

			byte[] hash = new byte[this.messDigest.GetDigestSize()];
			this.messDigest.DoFinal(hash, 0);

			return this.messSigner.verifySignature(hash, signature);
		}
	}

}
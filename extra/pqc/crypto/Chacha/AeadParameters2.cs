using Neuralia.Blockchains.Tools.Data.Arrays;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.Chacha {
	public class AeadParameters2
		: ICipherParameters
	{
		private readonly ByteArray associatedText;
		private readonly ByteArray nonce;
		private readonly KeyParameter2 key;
		private readonly int macSize;

		/**
         * Base constructor.
         *
         * @param key key to be used by underlying cipher
         * @param macSize macSize in bits
         * @param nonce nonce to be used
         */
		public AeadParameters2(KeyParameter2 key, int macSize, ByteArray nonce)
			: this(key, macSize, nonce, null)
		{
		}

		/**
		 * Base constructor.
		 *
		 * @param key key to be used by underlying cipher
		 * @param macSize macSize in bits
		 * @param nonce nonce to be used
		 * @param associatedText associated text, if any
		 */
		public AeadParameters2(
			KeyParameter2	key,
			int				macSize,
			ByteArray			nonce,
			ByteArray			associatedText)
		{
			this.key = key;
			this.nonce = nonce;
			this.macSize = macSize;
			this.associatedText = associatedText;
		}

		public virtual KeyParameter2 Key
		{
			get { return key; }
		}

		public virtual int MacSize
		{
			get { return macSize; }
		}

		public virtual ByteArray GetAssociatedText()
		{
			return associatedText;
		}

		public virtual ByteArray GetNonce()
		{
			return nonce;
		}
	}
}
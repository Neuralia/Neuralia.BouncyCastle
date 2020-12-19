using System;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.Chacha {
	/// <summary>
	/// copy to avoid the original's useless copying
	/// </summary>
	public class KeyParameter2
		: ICipherParameters
	{
		private readonly ByteArray key;

		public KeyParameter2(
			ByteArray key)
		{
			if (key == null)
				throw new ArgumentNullException("key");

			this.key = ByteArray.Wrap(key);
		}

		public KeyParameter2(
			ByteArray	key,
			int		keyOff,
			int		keyLen)
		{
			if (key == null)
				throw new ArgumentNullException("key");
			if (keyOff < 0 || keyOff > key.Length)
				throw new ArgumentOutOfRangeException("keyOff");
			if (keyLen < 0 || keyLen > (key.Length - keyOff))
				throw new ArgumentOutOfRangeException("keyLen");

			using var wrapper = ByteArray.Wrap(key);

			this.key = wrapper.Slice(keyOff, keyLen);
		}

		public ByteArray GetKey()
		{
			return key;
		}
	}
}
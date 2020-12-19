using System;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.Chacha {
	public class ParametersWithIV2
		: ICipherParameters
	{
		private readonly ICipherParameters parameters;
		private readonly ByteArray iv;

		public ParametersWithIV2(ICipherParameters parameters,
		                         ByteArray iv)
		{
			if (iv == null)
				throw new ArgumentNullException("iv");
			
			this.parameters = parameters;
			this.iv = iv;
		}

		public ByteArray GetIV()
		{
			return iv;
		}

		public ICipherParameters Parameters
		{
			get { return parameters; }
		}
	}
}
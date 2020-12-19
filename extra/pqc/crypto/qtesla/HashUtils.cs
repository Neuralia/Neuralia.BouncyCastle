using System;
using Neuralia.BouncyCastle.extra.crypto.digests;
using Org.BouncyCastle.Crypto.Digests;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {

	internal class HashUtils {

		public const int SECURE_HASH_ALGORITHM_KECCAK_128_RATE = 168;
		public const int SECURE_HASH_ALGORITHM_KECCAK_256_RATE = 136;

		/// <summary>
		///     *************************************************************************************************************************************************************
		///     Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That Generally Supports 128 Bits of Security
		///     Strength, If the Output is Sufficiently Long
		///     **************************************************************************************************************************************************************
		/// </summary>
		internal static void secureHashAlgorithmKECCAK128(sbyte[] output, int outputOffset, int outputLength, sbyte[] input, int inputOffset, int inputLength) {
			ShakeDigest dig = new ShakeDigest(128);
			dig.BlockUpdate((byte[]) (Array) input, inputOffset, inputLength);

			dig.DoFinal((byte[]) (Array) output, outputOffset, outputLength);
		}

		/// <summary>
		///     *************************************************************************************************************************************************************
		///     Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That Generally Supports 256 Bits of Security
		///     Strength, If the Output is Sufficiently Long
		///     **************************************************************************************************************************************************************
		/// </summary>
		internal static void secureHashAlgorithmKECCAK256(sbyte[] output, int outputOffset, int outputLength, sbyte[] input, int inputOffset, int inputLength) {
			ShakeDigest dig = new ShakeDigest(256);
			dig.BlockUpdate((byte[]) (Array) input, inputOffset, inputLength);

			dig.DoFinal((byte[]) (Array) output, outputOffset, outputLength);
		}

		/* Customizable Secure Hash Algorithm KECCAK 128 / Customizable Secure Hash Algorithm KECCAK 256 */

		internal static void customizableSecureHashAlgorithmKECCAK128Simple(sbyte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, sbyte[] input, int inputOffset, int inputLength) {
			CShakeDigest dig = new CShakeDigest(128, null, (byte[]) (Array) new[] {(sbyte) continuousTimeStochasticModelling, (sbyte) (continuousTimeStochasticModelling >> 8)});
			dig.BlockUpdate((byte[]) (Array) input, inputOffset, inputLength);

			dig.DoFinal((byte[]) (Array) output, outputOffset, outputLength);
		}

		internal static void customizableSecureHashAlgorithmKECCAK256Simple(sbyte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, sbyte[] input, int inputOffset, int inputLength) {
			CShakeDigest dig = new CShakeDigest(256, null, (byte[]) (Array) new[] {(sbyte) continuousTimeStochasticModelling, (sbyte) (continuousTimeStochasticModelling >> 8)});
			dig.BlockUpdate((byte[]) (Array) input, inputOffset, inputLength);

			dig.DoFinal((byte[]) (Array) output, outputOffset, outputLength);
		}
	}

}
using System;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.crypto.digests {
    /// <summary>
    ///     Implementation of SHAKE based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
    /// </summary>
    /// <remarks>
    ///     Following the naming conventions used in the C source code to enable easy review of the implementation.
    ///     also, taken from the java version, which fixes bugs in the C# version.
    /// </remarks>
    public class ShakeDigest2 : KeccakDigest2, IXof {

		public ShakeDigest2() : this(128) {
		}

		public ShakeDigest2(int bitLength) : base(CheckBitLength(bitLength)) {
		}

		public ShakeDigest2(ShakeDigest2 source) : base(source) {
		}

		public override string AlgorithmName => "SHAKE" + this.fixedOutputLength;

		public override int DoFinal(byte[] output, int outOff) {
			return this.DoFinal(output, outOff, this.GetDigestSize());
		}

		public virtual int DoFinal(byte[] output, int outOff, int outLen) {
			this.DoOutput(output, outOff, outLen);

			this.Reset();

			return outLen;
		}

		public virtual int DoOutput(byte[] output, int outOff, int outLen) {
			if(!this.squeezing) {
				this.AbsorbBits(0x0F, 4);
			}

			this.Squeeze(output, outOff, outLen * 8);

			return outLen;
		}

		private static int CheckBitLength(int bitLength) {
			switch(bitLength) {
				case 128:
				case 256:

					return bitLength;
				default:

					throw new ArgumentException(bitLength + " not supported for SHAKE", "bitLength");
			}
		}

		/*
		 * TODO Possible API change to support partial-byte suffixes.
		 */
		protected override int DoFinal(byte[] output, int outOff, byte partialByte, int partialBits) {
			return this.DoFinal(output, outOff, this.GetDigestSize(), partialByte, partialBits);
		}

		/*
		 * TODO Possible API change to support partial-byte suffixes.
		 */
		protected virtual int DoFinal(byte[] output, int outOff, int outLen, byte partialByte, int partialBits) {
			if((partialBits < 0) || (partialBits > 7)) {
				throw new ArgumentException("must be in the range [0,7]", "partialBits");
			}

			int finalInput = (partialByte & ((1 << partialBits) - 1)) | (0x0F << partialBits);
			Debug.Assert(finalInput >= 0);
			int finalBits = partialBits + 4;

			if(finalBits >= 8) {
				this.Absorb(new[] {(byte) finalInput}, 0, 1);
				finalBits  -=  8;
				finalInput >>= 8;
			}

			if(finalBits > 0) {
				this.AbsorbBits(finalInput, finalBits);
			}

			this.Squeeze(output, outOff, outLen * 8);

			this.Reset();

			return outLen;
		}

		public override IMemoable Copy() {
			return new ShakeDigest2(this);
		}
	}
}
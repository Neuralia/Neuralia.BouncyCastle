using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.crypto.digests {
	public class CShakeDigest : ShakeDigest2 {

		private static readonly byte[] padding = new byte[100];
		private readonly        byte[] diff;

		public CShakeDigest(int bitLength, byte[] N, byte[] S) : base(bitLength) {
			if(((N == null) || (N.Length == 0)) && ((S == null) || (S.Length == 0))) {
				this.diff = null;
			} else {
				this.diff = ArraysExtensions.Concatenate(this.leftEncode(this.rate / 8), this.encodeString(N), this.encodeString(S));
				this.diffPadAndAbsorb();
			}
		}

		private void diffPadAndAbsorb() {

			int blockSize = this.rate / 8;
			this.Absorb(this.diff, 0, this.diff.Length);

			int required = blockSize - (this.diff.Length % blockSize);

			while(required > padding.Length) {
				this.Absorb(padding, 0, padding.Length);
				required -= padding.Length;
			}

			this.Absorb(padding, 0, required);
		}

		private byte[] encodeString(byte[] str) {
			if((str == null) || (str.Length == 0)) {
				return this.leftEncode(0);
			}

			return Arrays.Concatenate(this.leftEncode(str.Length * 8), str);
		}

		private byte[] leftEncode(int strLen) {
			byte n = 0;

			for(int v = strLen; v != 0; v = v >> 8) {
				n++;
			}

			if(n == 0) {
				n = 1;
			}

			byte[] b = new byte[n + 1];

			b[0] = n;

			for(int i = 1; i <= n; i++) {
				b[i] = (byte) (strLen >> (8 * (i - 1)));
			}

			return b;
		}

		public override int DoOutput(byte[] @out, int outOff, int outLen) {
			if(this.diff != null) {
				if(!this.squeezing) {
					this.AbsorbBits(0x00, 2);
				}

				this.Squeeze(@out, outOff, outLen * 8);

				return outLen;
			}

			return base.DoOutput(@out, outOff, outLen);
		}

		public override void Reset() {
			base.Reset();

			if(this.diff != null) {
				this.diffPadAndAbsorb();
			}
		}
	}
}
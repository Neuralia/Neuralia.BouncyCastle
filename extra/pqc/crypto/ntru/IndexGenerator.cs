using System;
using Neuralia.Blockchains.Tools;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Org.BouncyCastle.Crypto;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	/// <summary>
	///     An implementation of the Index Generation Function in IEEE P1363.1.
	/// </summary>
	public class IndexGenerator {
		private          BitString  buf;
		private readonly int        c;
		private          int        counter;
		private readonly IDigest    hashAlg;
		private readonly int        hLen;
		private          bool       initialized;
		private readonly int        minCallsR;
		private readonly int        N;
		private          int        remLen;
		private readonly SafeArrayHandle seed = SafeArrayHandle.Create();
		private          int        totLen;

		/// <summary>
		///     Constructs a new index generator.
		/// </summary>
		/// <param name="seed">   a seed of arbitrary length to initialize the index generator with </param>
		/// <param name="params"> NTRUEncrypt parameters </param>
		internal IndexGenerator(SafeArrayHandle seed, NTRUEncryptionParameters @params) {
			this.seed      = seed;
			this.N         = @params.N;
			this.c         = @params.c;
			this.minCallsR = @params.minCallsR;

			this.totLen  = 0;
			this.remLen  = 0;
			this.counter = 0;
			this.hashAlg = @params.hashAlg;

			this.hLen        = this.hashAlg.GetDigestSize(); // hash length
			this.initialized = false;
		}

		/*
		 * Returns a number <code>i</code> such that <code>0 &lt;= i &lt; N</code>.
		 */
		internal virtual int nextIndex() {
			if(!this.initialized) {
				this.buf = new BitString();

				using(SafeArrayHandle hash = SafeArrayHandle.Create(this.hashAlg.GetDigestSize())) {

					while(this.counter < this.minCallsR) {
						this.appendHash(this.buf, hash);
						this.counter++;
					}

				}

				this.totLen      = this.minCallsR * 8 * this.hLen;
				this.remLen      = this.totLen;
				this.initialized = true;
			}

			while(true) {
				this.totLen += this.c;
				BitString M = this.buf.getTrailing(this.remLen);

				if(this.remLen < this.c) {
					int        tmpLen     = this.c       - this.remLen;
					int        cThreshold = this.counter + (((tmpLen + this.hLen) - 1) / this.hLen);

					using(SafeArrayHandle hash = SafeArrayHandle.Create(this.hashAlg.GetDigestSize())) {

						while(this.counter < cThreshold) {
							this.appendHash(M, hash);
							this.counter++;

							if(tmpLen > (8 * this.hLen)) {
								tmpLen -= 8 * this.hLen;
							}
						}

						this.remLen = (8 * this.hLen) - tmpLen;
						this.buf?.Dispose();

						this.buf = new BitString();
						this.buf.appendBits(hash);
					}
				} else {
					this.remLen -= this.c;
				}

				int i = M.getLeadingAsInt(this.c); // assume c<32
				M.Dispose();

				if(i < ((1 << this.c) - ((1 << this.c) % this.N))) {
					return i % this.N;
				}
			}
		}

		private void appendHash(BitString m, SafeArrayHandle hash) {
			this.hashAlg.BlockUpdate(this.seed.Bytes, this.seed.Offset, this.seed.Length);

			this.putInt(this.hashAlg, this.counter);
			
			byte[] tempHash = hash.ToExactByteArrayCopy();
			this.hashAlg.DoFinal(tempHash, 0);

			hash.Entry.CopyFrom(ref tempHash, 0, 0, tempHash.Length);

			m.appendBits(hash);
		}

		private void putInt(IDigest hashAlg, int counter) {
			hashAlg.Update((byte) (counter >> 24));
			hashAlg.Update((byte) (counter >> 16));
			hashAlg.Update((byte) (counter >> 8));
			hashAlg.Update((byte) counter);
		}

		private static SafeArrayHandle copyOf(SafeArrayHandle src, int len) {
			SafeArrayHandle tmp = SafeArrayHandle.Create(len);

			tmp.Entry.CopyFrom(src.Entry, 0, 0, len < src.Length ? len : src.Length);

			return tmp;
		}

		/// <summary>
		///     Represents a string of bits and supports appending, reading the head, and reading the tail.
		/// </summary>
		public class BitString : IDisposableExtended {
			internal SafeArrayHandle bytes = SafeArrayHandle.Create(4);
			internal int        lastByteBits; // lastByteBits <= 8
			internal int        numBytes;     // includes the last byte even if only some of its bits are used

			public virtual SafeArrayHandle Bytes => (SafeArrayHandle) this.bytes.Clone();

			/// <summary>
			///     Appends all bits in a byte array to the end of the bit string.
			/// </summary>
			/// <param name="bytes"> a byte array </param>
			internal virtual void appendBits(SafeArrayHandle bytes) {
				for(int i = 0; i != bytes.Length; i++) {
					this.appendBits(bytes[i]);
				}
			}

			/// <summary>
			///     Appends all bits in a byte to the end of the bit string.
			/// </summary>
			/// <param name="b"> a byte </param>
			public virtual void appendBits(byte b) {
				if(this.numBytes == this.bytes.Length) {
					this.bytes = copyOf(this.bytes, 2 * this.bytes.Length);
				}

				if(this.numBytes == 0) {
					this.numBytes     = 1;
					this.bytes[0]     = b;
					this.lastByteBits = 8;
				} else if(this.lastByteBits == 8) {
					this.bytes[this.numBytes++] = b;
				} else {
					int s = 8 - this.lastByteBits;
					this.bytes[this.numBytes - 1] |= (byte) ((b & 0xFF) << this.lastByteBits);
					this.bytes[this.numBytes++]   =  (byte) ((b & 0xFF) >> s);
				}
			}

			/// <summary>
			///     Returns the last <code>numBits</code> bits from the end of the bit string.
			/// </summary>
			/// <param name="numBits"> number of bits </param>
			/// <returns> a new <code>BitString</code> of length <code>numBits</code> </returns>
			public virtual BitString getTrailing(int numBits) {
				BitString newStr = new BitString();
				newStr.numBytes = (numBits + 7) / 8;
				newStr.bytes = SafeArrayHandle.Create(newStr.numBytes);

				for(int i = 0; i < newStr.numBytes; i++) {
					newStr.bytes[i] = this.bytes[i];
				}

				newStr.lastByteBits = numBits % 8;

				if(newStr.lastByteBits == 0) {
					newStr.lastByteBits = 8;
				} else {
					int s = 32 - newStr.lastByteBits;
					newStr.bytes[newStr.numBytes - 1] = (byte) (int) (((uint) newStr.bytes[newStr.numBytes - 1] << s) >> s);
				}

				return newStr;
			}

			/// <summary>
			///     Returns up to 32 bits from the beginning of the bit string.
			/// </summary>
			/// <param name="numBits"> number of bits </param>
			/// <returns> an <code>int</code> whose lower <code>numBits</code> bits are the beginning of the bit string </returns>
			public virtual int getLeadingAsInt(int numBits) {
				int startBit  = (((this.numBytes - 1) * 8) + this.lastByteBits) - numBits;
				int startByte = startBit / 8;

				int startBitInStartByte = startBit % 8;
				int sum                 = (int) ((uint) (this.bytes[startByte] & 0xFF) >> startBitInStartByte);
				int shift               = 8 - startBitInStartByte;

				for(int i = startByte + 1; i < this.numBytes; i++) {
					sum   |= (this.bytes[i] & 0xFF) << shift;
					shift += 8;
				}

				return sum;
			}

		#region disposable

			public bool IsDisposed { get; private set; }

			public void Dispose() {
				this.Dispose(true);
				GC.SuppressFinalize(this);
			}

			private void Dispose(bool disposing) {
				

				if(disposing && !this.IsDisposed) {
					try {
						this.bytes.Dispose();

					} finally {
						this.IsDisposed = true;
					}
				}
			}

			~BitString() {
				this.Dispose(false);
			}

		#endregion

		}
	}
}
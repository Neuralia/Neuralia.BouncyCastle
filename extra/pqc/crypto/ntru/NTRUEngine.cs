using System;
using Neuralia.Blockchains.Tools;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial;
using Neuralia.BouncyCastle.extra.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	/// <summary>
	///     Encrypts, decrypts data and generates key pairs.
	///     <br>
	///         The parameter p is hardcoded to 3.
	/// </summary>
	public class NTRUEngine : IDisposableExtended {
		private bool                               forEncryption;
		private NTRUEncryptionParameters           @params;
		private NTRUEncryptionPrivateKeyParameters privKey;
		private NTRUEncryptionPublicKeyParameters  pubKey;
		private SecureRandom                       random;

		public string AlgorithmName => "NTRU";

		public virtual void Init(bool forEncryption, ICipherParameters parameters, SecureRandom random = null) {
			this.forEncryption = forEncryption;

			if(forEncryption) {
				if(parameters is ParametersWithRandom) {
					ParametersWithRandom p = (ParametersWithRandom) parameters;

					this.random = p.Random;
					this.pubKey = (NTRUEncryptionPublicKeyParameters) p.Parameters;
				} else {
					
					this.random = random ?? new BetterSecureRandom();
					this.pubKey = (NTRUEncryptionPublicKeyParameters) parameters;
				}

				this.@params = this.pubKey.Parameters;
			} else {
				this.privKey = (NTRUEncryptionPrivateKeyParameters) parameters;
				this.@params = this.privKey.Parameters;
			}
		}

		public virtual int GetInputBlockSize() {
			return this.@params.maxMsgLenBytes;
		}

		public virtual int GetOutputBlockSize() {
			return ((this.@params.N * this.log2(this.@params.q)) + 7) / 8;
		}

		public SafeArrayHandle ProcessBlock(SafeArrayHandle input) {

			if(this.forEncryption) {
				return this.encrypt(input, this.pubKey);
			}

			return this.decrypt(input, this.privKey);

		}

		/// <summary>
		///     Encrypts a message.<br />
		///     See P1363.1 section 9.2.2.
		/// </summary>
		/// <param name="m">      The message to encrypt </param>
		/// <param name="pubKey"> the public key to encrypt the message with </param>
		/// <returns> the encrypted message </returns>
		private SafeArrayHandle encrypt(SafeArrayHandle m, NTRUEncryptionPublicKeyParameters pubKey) {
			IntegerPolynomial pub = pubKey.h;
			int               N   = this.@params.N;
			int               q   = this.@params.q;

			int        maxLenBytes   = this.@params.maxMsgLenBytes;
			int        db            = this.@params.db;
			int        bufferLenBits = this.@params.bufferLenBits;
			int        dm0           = this.@params.dm0;
			int        pkLen         = this.@params.pkLen;
			int        minCallsMask  = this.@params.minCallsMask;
			bool       hashSeed      = this.@params.hashSeed;
			SafeArrayHandle oid           = this.@params.oid;

			int l = m.Length;

			if(maxLenBytes > 255) {
				throw new ArgumentException("llen values bigger than 1 are not supported");
			}

			if(l > maxLenBytes) {
				throw new DataLengthException("Message too long: " + l + ">" + maxLenBytes);
			}

			while(true) {
				// M = b|octL|m|p0
				SafeArrayHandle b = ByteArray.Create(db / 8);
				this.random.NextBytes(b.Bytes, b.Offset, b.Length);
				SafeArrayHandle p0 = ByteArray.Create((maxLenBytes + 1) - l);
				SafeArrayHandle M  = ByteArray.Create(bufferLenBits / 8);

				b.Entry.CopyTo(M.Entry, 0, 0, b.Length);

				M[b.Length] = (byte) l;
				m.Entry.CopyTo(M.Entry, 0, b.Length      + 1, m.Length);
				p0.Entry.CopyTo(M.Entry, 0, b.Length + 1 + m.Length, p0.Length);

				IntegerPolynomial mTrin = IntegerPolynomial.fromBinary3Sves(M, N);

				// sData = OID|m|b|hTrunc
				SafeArrayHandle bh     = pub.toBinary(q);
				SafeArrayHandle hTrunc = this.copyOf(bh, pkLen / 8);
				SafeArrayHandle sData  = this.buildSData(oid, m, l, b, hTrunc);

				IPolynomial       r  = this.generateBlindingPoly(sData, M);
				IntegerPolynomial R  = r.mult(pub, q);
				IntegerPolynomial R4 = R.clone();
				R4.modPositive(4);
				SafeArrayHandle        oR4  = R4.toBinary(4);
				IntegerPolynomial mask = this.MGF(oR4, N, minCallsMask, hashSeed);
				mTrin.add(mask);
				mTrin.mod3();

				if(mTrin.count(-1) < dm0) {
					continue;
				}

				if(mTrin.count(0) < dm0) {
					continue;
				}

				if(mTrin.count(1) < dm0) {
					continue;
				}

				b.Return();
				p0.Return();
				M.Return();
				bh.Return();
				hTrunc.Return();
				sData.Return();
				oR4.Return();

				R.add(mTrin, q);
				R.ensurePositive(q);

				return R.toBinary(q);
			}
		}

		private SafeArrayHandle buildSData(SafeArrayHandle oid, SafeArrayHandle m, int l, SafeArrayHandle b, SafeArrayHandle hTrunc) {
			SafeArrayHandle sData = ByteArray.Create(oid.Length + l + b.Length + hTrunc.Length);

			oid.Entry.CopyTo(sData.Entry, 0, 0, oid.Length);
			m.Entry.CopyTo(sData.Entry, 0, oid.Length, m.Length);
			b.Entry.CopyTo(sData.Entry, 0, oid.Length                 + m.Length, b.Length);
			hTrunc.Entry.CopyTo(sData.Entry, 0, oid.Length + m.Length + b.Length, hTrunc.Length);

			return sData;
		}

		protected internal virtual IntegerPolynomial encrypt(IntegerPolynomial m, TernaryPolynomial r, IntegerPolynomial pubKey) {
			IntegerPolynomial e = r.mult(pubKey, this.@params.q);
			e.add(m, this.@params.q);
			e.ensurePositive(this.@params.q);

			return e;
		}

		/// <summary>
		///     Deterministically generates a blinding polynomial from a seed and a message representative.
		/// </summary>
		/// <param name="seed"> </param>
		/// <param name="M">    message representative </param>
		/// <returns> a blinding polynomial </returns>
		private IPolynomial generateBlindingPoly(SafeArrayHandle seed, SafeArrayHandle M) {
			IndexGenerator ig = new IndexGenerator(seed, this.@params);

			if(this.@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT) {
				SparseTernaryPolynomial r1 = new SparseTernaryPolynomial(this.generateBlindingCoeffs(ig, this.@params.dr1));
				SparseTernaryPolynomial r2 = new SparseTernaryPolynomial(this.generateBlindingCoeffs(ig, this.@params.dr2));
				SparseTernaryPolynomial r3 = new SparseTernaryPolynomial(this.generateBlindingCoeffs(ig, this.@params.dr3));

				return new ProductFormPolynomial(r1, r2, r3);
			}

			int   dr     = this.@params.dr;
			bool  sparse = this.@params.sparse;
			int[] r      = this.generateBlindingCoeffs(ig, dr);

			if(sparse) {
				return new SparseTernaryPolynomial(r);
			}

			return new DenseTernaryPolynomial(r);
		}

		/// <summary>
		///     Generates an <code>int</code> array containing <code>dr</code> elements equal to <code>1</code>
		///     and <code>dr</code> elements equal to <code>-1</code> using an index generator.
		/// </summary>
		/// <param name="ig"> an index generator </param>
		/// <param name="dr"> number of ones / negative ones </param>
		/// <returns> an array containing numbers between <code>-1</code> and <code>1</code> </returns>
		private int[] generateBlindingCoeffs(IndexGenerator ig, int dr) {
			int N = this.@params.N;

			int[] r = new int[N];

			for(int coeff = -1; coeff <= 1; coeff += 2) {
				int t = 0;

				while(t < dr) {
					int i = ig.nextIndex();

					if(r[i] == 0) {
						r[i] = coeff;
						t++;
					}
				}
			}

			return r;
		}

		/// <summary>
		///     An implementation of MGF-TP-1 from P1363.1 section 8.4.1.1.
		/// </summary>
		/// <param name="seed"> </param>
		/// <param name="N"> </param>
		/// <param name="minCallsR"> </param>
		/// <param name="hashSeed">  whether to hash the seed </param>
		private IntegerPolynomial MGF(SafeArrayHandle seed, int N, int minCallsR, bool hashSeed) {
			IDigest    hashAlg = this.@params.hashAlg;
			int        hashLen = hashAlg.GetDigestSize();
			SafeArrayHandle buf     = ByteArray.Create(minCallsR * hashLen);
			SafeArrayHandle Z       = hashSeed ? this.calcHash(hashAlg, seed) : seed;
			int        counter = 0;

			while(counter < minCallsR) {
				hashAlg.BlockUpdate(Z.ToExactByteArray(), 0, Z.Length);
				this.putInt(hashAlg, counter);

				SafeArrayHandle hash = this.calcHash(hashAlg);
				hash.Entry.CopyTo(buf.Entry, 0, counter * hashLen, hashLen);

				hash.Return();
				counter++;
			}

			IntegerPolynomial i = new IntegerPolynomial(N);

			while(true) {
				int cur = 0;

				for(int index = 0; index != buf.Length; index++) {
					int O = buf[index] & 0xFF;

					if(O >= 243) // 243 = 3^5
					{
						continue;
					}

					for(int terIdx = 0; terIdx < 4; terIdx++) {
						int rem3 = O % 3;
						i.coeffs[cur] = rem3 - 1;
						cur++;

						if(cur == N) {
							return i;
						}

						O = (O - rem3) / 3;
					}

					i.coeffs[cur] = O - 1;
					cur++;

					if(cur == N) {
						buf.Return();
						Z.Return();

						return i;
					}
				}

				if(cur >= N) {
					return i;
				}

				hashAlg.BlockUpdate(Z.ToExactByteArrayCopy(), 0, Z.Length);
				this.putInt(hashAlg, counter);

				SafeArrayHandle hash = this.calcHash(hashAlg);

				buf?.Return();

				buf = hash;

				counter++;
			}
		}

		private void putInt(IDigest hashAlg, int counter) {
			hashAlg.Update((byte) (counter >> 24));
			hashAlg.Update((byte) (counter >> 16));
			hashAlg.Update((byte) (counter >> 8));
			hashAlg.Update((byte) counter);
		}

		private SafeArrayHandle calcHash(IDigest hashAlg) {

			byte[] tempHash = new byte[hashAlg.GetDigestSize()];
			hashAlg.DoFinal(tempHash, 0);

			SafeArrayHandle resultHash = ByteArray.Create(tempHash.Length);
			resultHash.Entry.CopyFrom(ref tempHash, 0, 0, tempHash.Length);

			return resultHash;
		}

		private SafeArrayHandle calcHash(IDigest hashAlg, SafeArrayHandle input) {

			hashAlg.BlockUpdate(input.Bytes, input.Offset, input.Length);

			return this.calcHash(hashAlg);
		}

		/// <summary>
		///     Decrypts a message.<br />
		///     See P1363.1 section 9.2.3.
		/// </summary>
		/// <param name="data"> The message to decrypt </param>
		/// <param name="privKey">   the corresponding private key </param>
		/// <returns> the decrypted message </returns>
		/// <exception cref="InvalidCipherTextException">
		///     if  the encrypted data is invalid, or <code>maxLenBytes</code> is greater
		///     than 255
		/// </exception>
		private SafeArrayHandle decrypt(SafeArrayHandle data, NTRUEncryptionPrivateKeyParameters privKey) {
			IPolynomial       priv_t         = privKey.t;
			IntegerPolynomial priv_fp        = privKey.fp;
			IntegerPolynomial pub            = privKey.h;
			int               N              = this.@params.N;
			int               q              = this.@params.q;
			int               db             = this.@params.db;
			int               maxMsgLenBytes = this.@params.maxMsgLenBytes;
			int               dm0            = this.@params.dm0;
			int               pkLen          = this.@params.pkLen;
			int               minCallsMask   = this.@params.minCallsMask;
			bool              hashSeed       = this.@params.hashSeed;
			SafeArrayHandle        oid            = this.@params.oid;

			if(maxMsgLenBytes > 255) {
				throw new DataLengthException("maxMsgLenBytes values bigger than 255 are not supported");
			}

			int bLen = db / 8;

			IntegerPolynomial e  = IntegerPolynomial.fromBinary(data, N, q);
			IntegerPolynomial ci = this.decrypt(e, priv_t, priv_fp);

			if(ci.count(-1) < dm0) {
				throw new InvalidCipherTextException("Less than dm0 coefficients equal -1");
			}

			if(ci.count(0) < dm0) {
				throw new InvalidCipherTextException("Less than dm0 coefficients equal 0");
			}

			if(ci.count(1) < dm0) {
				throw new InvalidCipherTextException("Less than dm0 coefficients equal 1");
			}

			IntegerPolynomial cR = e.clone();
			cR.sub(ci);
			cR.modPositive(q);
			IntegerPolynomial cR4 = cR.clone();
			cR4.modPositive(4);
			SafeArrayHandle        coR4   = cR4.toBinary(4);
			IntegerPolynomial mask   = this.MGF(coR4, N, minCallsMask, hashSeed);
			IntegerPolynomial cMTrin = ci;
			cMTrin.sub(mask);
			cMTrin.mod3();
			SafeArrayHandle cM = cMTrin.toBinary3Sves();

			SafeArrayHandle cb = ByteArray.Create(bLen);
			cM.Entry.CopyTo(cb.Entry, 0, 0, bLen);

			int cl = cM[bLen] & 0xFF; // llen=1, so read one byte

			if(cl > maxMsgLenBytes) {
				throw new InvalidCipherTextException("Message too long: " + cl + ">" + maxMsgLenBytes);
			}

			SafeArrayHandle cm = ByteArray.Create(cl);
			cM.Entry.CopyTo(cm.Entry, bLen + 1, 0, cl);

			SafeArrayHandle p0 = ByteArray.Create(cM.Length - (bLen + 1 + cl));
			cM.Entry.CopyTo(p0.Entry, bLen + 1 + cl, 0, p0.Length);

			SafeArrayHandle tempempty = ByteArray.Create(p0.Length);

			
			if(!FastArrays.ConstantTimeAreEqual(p0, tempempty)) {
				throw new InvalidCipherTextException("The message is not followed by zeroes");
			}

			tempempty.Return();

			// sData = OID|m|b|hTrunc
			SafeArrayHandle bh     = pub.toBinary(q);
			SafeArrayHandle hTrunc = this.copyOf(bh, pkLen / 8);
			SafeArrayHandle sData  = this.buildSData(oid, cm, cl, cb, hTrunc);

			IPolynomial       cr      = this.generateBlindingPoly(sData, cm);
			IntegerPolynomial cRPrime = cr.mult(pub);
			cRPrime.modPositive(q);

			if(!cRPrime.Equals(cR)) {
				throw new InvalidCipherTextException("Invalid message encoding");
			}

			coR4.Return();
			cM.Return();
			cb.Return();

			p0.Return();
			bh.Return();
			hTrunc.Return();
			sData.Return();

			return cm;
		}

		/// <param name="e"> </param>
		/// <param name="priv_t">
		///     a polynomial such that if <code>fastFp=true</code>, <code>f=1+3*priv_t</code>; otherwise,
		///     <code>f=priv_t</code>
		/// </param>
		/// <param name="priv_fp"> </param>
		/// <returns> an IntegerPolynomial representing the output. </returns>
		protected internal virtual IntegerPolynomial decrypt(IntegerPolynomial e, IPolynomial priv_t, IntegerPolynomial priv_fp) {
			IntegerPolynomial a;

			if(this.@params.fastFp) {
				a = priv_t.mult(e, this.@params.q);
				a.mult(3);
				a.add(e);
			} else {
				a = priv_t.mult(e, this.@params.q);
			}

			a.center0(this.@params.q);
			a.mod3();

			IntegerPolynomial c = this.@params.fastFp ? a : new DenseTernaryPolynomial(a).mult(priv_fp, 3);
			c.center0(3);

			return c;
		}

		private SafeArrayHandle copyOf(SafeArrayHandle src, int len) {
			SafeArrayHandle tmp = ByteArray.Create(len);

			src.Entry.CopyTo(tmp.Entry, 0, 0, len < src.Length ? len : src.Length);

			return tmp;
		}

		private int log2(int value) {
			if(value == 2048) {
				return 11;
			}

			throw new InvalidOperationException("log2 not fully implemented");
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

				} finally {
					this.IsDisposed = true;
				}
			}
		}

		~NTRUEngine() {
			this.Dispose(false);
		}

	#endregion

	}
}
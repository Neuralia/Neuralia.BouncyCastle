using System;
using System.IO;
using System.Text;
using Neuralia.Blockchains.Tools;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.Blockchains.Tools.Serialization;

using Neuralia.BouncyCastle.extra.crypto.digests;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial;
using Neuralia.BouncyCastle.extra.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	/// <summary>
	///     A set of parameters for NTRUEncrypt. Several predefined parameter sets are available and new ones can be created as
	///     well.
	/// </summary>
	public class NTRUEncryptionKeyGenerationParameters : KeyGenerationParameters, ICloneable, IDisposableExtended {

		public enum NTRUEncryptionKeyGenerationParametersTypes {
			EES1087EP2, EES1171EP1, EES1499EP1,
			EES1499EP1_EXT,
			APR2011_439,
			APR2011_439_FAST,
			APR2011_743,
			APR2011_743_FAST
		}
		public static NTRUEncryptionKeyGenerationParameters CreateNTRUEncryptionKeyGenerationParameters(NTRUEncryptionKeyGenerationParametersTypes type, Func< IDigest> digest256Generator, Func<IDigest> digest512Generator) {

			switch(type) {
				//     A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size.
				case NTRUEncryptionKeyGenerationParametersTypes.EES1087EP2:
					return new NTRUEncryptionKeyGenerationParameters(1087, 2048, 120, 120, 256, 13, 25, 14, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 6, 3}), true, false, digest512Generator());
					break;
				// A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key
				//     size and encryption/decryption speed.
				case NTRUEncryptionKeyGenerationParametersTypes.EES1171EP1:
					return new NTRUEncryptionKeyGenerationParameters(1171, 2048, 106, 106, 256, 13, 20, 15, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 6, 4}), true, false, digest512Generator());
					break;
				case NTRUEncryptionKeyGenerationParametersTypes.EES1499EP1:
					//    A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for
					//    encryption/decryption speed.

					return new NTRUEncryptionKeyGenerationParameters(1499, 2048, 79, 79, 256, 13, 17, 19, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 6, 5}), true, false, digest512Generator());
					break;
				case NTRUEncryptionKeyGenerationParametersTypes.EES1499EP1_EXT:
					//    A conservative (in terms of security) parameter set that gives 512 bits of security and is optimized for
					//    encryption/decryption speed.
		
					return new NTRUEncryptionKeyGenerationParameters(1499, 2048, 146, 146, 512, 13, 41, 19, true, SafeArrayHandle.WrapAndOwn(new byte[] {2, 20, 2, 1, 43, 54, 66}), true, true, digest512Generator());

					break;
				case NTRUEncryptionKeyGenerationParametersTypes.APR2011_439:
							
					//    A parameter set that gives 128 bits of security and uses simple ternary polynomials.
		
					return new NTRUEncryptionKeyGenerationParameters(439, 2048, 146, 130, 128, 9, 32, 9, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 7, 101}), true, false, digest256Generator());

					break;
				case NTRUEncryptionKeyGenerationParametersTypes.APR2011_439_FAST:
					//    Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials and
					//    <code>f=1+pF</code>.
		
					return new NTRUEncryptionKeyGenerationParameters(439, 2048, 9, 8, 5, 130, 128, 9, 32, 9, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 7, 101}), true, true, digest256Generator());


					break;
				case NTRUEncryptionKeyGenerationParametersTypes.APR2011_743:
					//    A parameter set that gives 256 bits of security and uses simple ternary polynomials.
		
					return new NTRUEncryptionKeyGenerationParameters(743, 2048, 248, 220, 512, 10, 27, 14, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 7, 105}), false, false, digest512Generator());

					break;
				case NTRUEncryptionKeyGenerationParametersTypes.APR2011_743_FAST:
					//    Like <code>APR2011_743</code>, this parameter set gives 256 bits of security but uses product-form polynomials and
					//    <code>f=1+pF</code>.
		
					return new NTRUEncryptionKeyGenerationParameters(743, 2048, 11, 11, 15, 220, 512, 10, 27, 14, true, SafeArrayHandle.WrapAndOwn(new byte[] {0, 7, 105}), false, true, digest512Generator());

					break;
				default:
					throw new ArgumentException();
			}
		}


		public   int     bufferLenBits;
		internal int     bufferLenTrits;
		public   int     c;
		public   int     db;
		public   int     dg;
		public   int     dm0;
		public   int     dr;
		public   int     dr1;
		public   int     dr2;
		public   int     dr3;
		public   bool    fastFp;
		public   IDigest hashAlg;
		public   bool    hashSeed;
		internal int     llen;
		public   int     maxMsgLenBytes;
		public   int     minCallsMask;
		public   int     minCallsR;

		public int        N, q, df, df1, df2, df3;
		public readonly SafeArrayHandle oid = SafeArrayHandle.Create();
		public int        pkLen;
		public int        polyType;
		public bool       sparse;

		/// <summary>
		///     Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
		/// </summary>
		/// <param name="N">            number of polynomial coefficients </param>
		/// <param name="q">            modulus </param>
		/// <param name="df">           number of ones in the private polynomial <code>f</code> </param>
		/// <param name="dm0">
		///     minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the
		///     last encryption step
		/// </param>
		/// <param name="db">           number of random bits to prepend to the message </param>
		/// <param name="c">            a parameter for the Index Generation Function (<seealso cref="IndexGenerator" />) </param>
		/// <param name="minCallsR">    minimum number of hash calls for the IGF to make </param>
		/// <param name="minCallsMask"> minimum number of calls to generate the masking polynomial </param>
		/// <param name="hashSeed">     whether to hash the seed in the MGF first (true) or use the seed directly (false) </param>
		/// <param name="oid">          three bytes that uniquely identify the parameter set </param>
		/// <param name="sparse">
		///     whether to treat ternary polynomials as sparsely populated (
		///     <seealso cref="SparseTernaryPolynomial" /> vs <seealso cref="DenseTernaryPolynomial" />)
		/// </param>
		/// <param name="fastFp">
		///     whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is
		///     ternary (false)
		/// </param>
		/// <param name="hashAlg">
		///     a valid identifier for a <code>java.security.MessageDigest</code> instance such as
		///     <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
		/// </param>
		public NTRUEncryptionKeyGenerationParameters(int N, int q, int df, int dm0, int db, int c, int minCallsR, int minCallsMask, bool hashSeed, SafeArrayHandle oid, bool sparse, bool fastFp, IDigest hashAlg) : base(new BetterSecureRandom(), db) {
			this.N            = N;
			this.q            = q;
			this.df           = df;
			this.db           = db;
			this.dm0          = dm0;
			this.c            = c;
			this.minCallsR    = minCallsR;
			this.minCallsMask = minCallsMask;
			this.hashSeed     = hashSeed;
			this.oid          = oid;
			this.sparse       = sparse;
			this.fastFp       = fastFp;
			this.polyType     = NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE;
			this.hashAlg      = hashAlg;
			this.init();
		}

		/// <summary>
		///     Constructs a parameter set that uses product-form private keys (i.e. <code>polyType=PRODUCT</code>).
		/// </summary>
		/// <param name="N">            number of polynomial coefficients </param>
		/// <param name="q">            modulus </param>
		/// <param name="df1">          number of ones in the private polynomial <code>f1</code> </param>
		/// <param name="df2">          number of ones in the private polynomial <code>f2</code> </param>
		/// <param name="df3">          number of ones in the private polynomial <code>f3</code> </param>
		/// <param name="dm0">
		///     minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the
		///     last encryption step
		/// </param>
		/// <param name="db">           number of random bits to prepend to the message </param>
		/// <param name="c">            a parameter for the Index Generation Function (<seealso cref="IndexGenerator" />) </param>
		/// <param name="minCallsR">    minimum number of hash calls for the IGF to make </param>
		/// <param name="minCallsMask"> minimum number of calls to generate the masking polynomial </param>
		/// <param name="hashSeed">     whether to hash the seed in the MGF first (true) or use the seed directly (false) </param>
		/// <param name="oid">          three bytes that uniquely identify the parameter set </param>
		/// <param name="sparse">
		///     whether to treat ternary polynomials as sparsely populated (
		///     <seealso cref="SparseTernaryPolynomial" /> vs <seealso cref="DenseTernaryPolynomial" />)
		/// </param>
		/// <param name="fastFp">
		///     whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is
		///     ternary (false)
		/// </param>
		/// <param name="hashAlg">
		///     a valid identifier for a <code>java.security.MessageDigest</code> instance such as
		///     <code>SHA-256</code>
		/// </param>
		public NTRUEncryptionKeyGenerationParameters(int N, int q, int df1, int df2, int df3, int dm0, int db, int c, int minCallsR, int minCallsMask, bool hashSeed, SafeArrayHandle oid, bool sparse, bool fastFp, IDigest hashAlg) : base(new BetterSecureRandom(), db) {

			this.N            = N;
			this.q            = q;
			this.df1          = df1;
			this.df2          = df2;
			this.df3          = df3;
			this.db           = db;
			this.dm0          = dm0;
			this.c            = c;
			this.minCallsR    = minCallsR;
			this.minCallsMask = minCallsMask;
			this.hashSeed     = hashSeed;
			this.oid          = oid;
			this.sparse       = sparse;
			this.fastFp       = fastFp;
			this.polyType     = NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT;
			this.hashAlg      = hashAlg;
			this.init();
		}

		/// <summary>
		///     Reads a parameter set from an input stream.
		/// </summary>
		/// <param name="is"> an input stream </param>
		/// <exception cref="IOException"> </exception>
		public NTRUEncryptionKeyGenerationParameters(IDataRehydrator rehydrator, Func<string, IDigest> digestGenerator) : base(new BetterSecureRandom(), -1) {

			this.N            = rehydrator.ReadInt();
			this.q            = rehydrator.ReadInt();
			this.df           = rehydrator.ReadInt();
			this.df1          = rehydrator.ReadInt();
			this.df2          = rehydrator.ReadInt();
			this.df3          = rehydrator.ReadInt();
			this.db           = rehydrator.ReadInt();
			this.dm0          = rehydrator.ReadInt();
			this.c            = rehydrator.ReadInt();
			this.minCallsR    = rehydrator.ReadInt();
			this.minCallsMask = rehydrator.ReadInt();
			this.hashSeed     = rehydrator.ReadBool();
			this.oid          = (SafeArrayHandle)rehydrator.ReadNonNullableArray();

			this.sparse   = rehydrator.ReadBool();
			this.fastFp   = rehydrator.ReadBool();
			this.polyType = rehydrator.ReadInt();

			string alg = rehydrator.ReadString();

			this.hashAlg = digestGenerator(alg);

			this.init();
		}

		public virtual NTRUEncryptionParameters EncryptionParameters {
			get {
				if(this.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE) {
					return new NTRUEncryptionParameters(this.N, this.q, this.df, this.dm0, this.db, this.c, this.minCallsR, this.minCallsMask, this.hashSeed, this.oid, this.sparse, this.fastFp, this.hashAlg);
				}

				return new NTRUEncryptionParameters(this.N, this.q, this.df1, this.df2, this.df3, this.dm0, this.db, this.c, this.minCallsR, this.minCallsMask, this.hashSeed, this.oid, this.sparse, this.fastFp, this.hashAlg);
			}
		}

		/// <summary>
		///     Returns the maximum length a plaintext message can be with this parameter set.
		/// </summary>
		/// <returns> the maximum length in bytes </returns>
		public virtual int MaxMessageLength => this.maxMsgLenBytes;

		public virtual object Clone() {
			if(this.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE) {
				return new NTRUEncryptionKeyGenerationParameters(this.N, this.q, this.df, this.dm0, this.db, this.c, this.minCallsR, this.minCallsMask, this.hashSeed, this.oid, this.sparse, this.fastFp, this.hashAlg);
			}

			return new NTRUEncryptionKeyGenerationParameters(this.N, this.q, this.df1, this.df2, this.df3, this.dm0, this.db, this.c, this.minCallsR, this.minCallsMask, this.hashSeed, this.oid, this.sparse, this.fastFp, this.hashAlg);
		}

		private void init() {
			this.dr             = this.df;
			this.dr1            = this.df1;
			this.dr2            = this.df2;
			this.dr3            = this.df3;
			this.dg             = this.N / 3;
			this.llen           = 1; // ceil(log2(maxMsgLenBytes))
			this.maxMsgLenBytes = ((this.N * 3) / 2 / 8) - this.llen - (this.db / 8) - 1;
			this.bufferLenBits  = (((((this.N * 3) / 2) + 7) / 8) * 8)               + 1;
			this.bufferLenTrits = this.N                                             - 1;
			this.pkLen          = this.db;
		}

		/// <summary>
		///     Writes the parameter set to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		public virtual void writeTo(IDataDehydrator dehydrator) {
			dehydrator.Write(this.N);
			dehydrator.Write(this.q);
			dehydrator.Write(this.df);
			dehydrator.Write(this.df1);
			dehydrator.Write(this.df2);
			dehydrator.Write(this.df3);
			dehydrator.Write(this.db);
			dehydrator.Write(this.dm0);
			dehydrator.Write(this.c);
			dehydrator.Write(this.minCallsR);
			dehydrator.Write(this.minCallsMask);
			dehydrator.Write(this.hashSeed);
			dehydrator.WriteNonNullable(this.oid);
			dehydrator.Write(this.sparse);
			dehydrator.Write(this.fastFp);
			dehydrator.Write(this.polyType);
			dehydrator.Write(this.hashAlg.AlgorithmName);
		}

		public override int GetHashCode() {
			const int prime  = 31;
			int       result = 1;
			result = (prime * result) + this.N;
			result = (prime * result) + this.bufferLenBits;
			result = (prime * result) + this.bufferLenTrits;
			result = (prime * result) + this.c;
			result = (prime * result) + this.db;
			result = (prime * result) + this.df;
			result = (prime * result) + this.df1;
			result = (prime * result) + this.df2;
			result = (prime * result) + this.df3;
			result = (prime * result) + this.dg;
			result = (prime * result) + this.dm0;
			result = (prime * result) + this.dr;
			result = (prime * result) + this.dr1;
			result = (prime * result) + this.dr2;
			result = (prime * result) + this.dr3;
			result = (prime * result) + (this.fastFp ? 1231 : 1237);
			result = (prime * result) + (this.hashAlg == null ? 0 : this.hashAlg.AlgorithmName.GetHashCode());
			result = (prime * result) + (this.hashSeed ? 1231 : 1237);
			result = (prime * result) + this.llen;
			result = (prime * result) + this.maxMsgLenBytes;
			result = (prime * result) + this.minCallsMask;
			result = (prime * result) + this.minCallsR;
			result = (prime * result) + Arrays.GetHashCode(this.oid.Span.ToArray());
			result = (prime * result) + this.pkLen;
			result = (prime * result) + this.polyType;
			result = (prime * result) + this.q;
			result = (prime * result) + (this.sparse ? 1231 : 1237);

			return result;
		}

		public override bool Equals(object obj) {
			if(this == obj) {
				return true;
			}

			if(obj == null) {
				return false;
			}

			if(this.GetType() != obj.GetType()) {
				return false;
			}

			NTRUEncryptionKeyGenerationParameters other = (NTRUEncryptionKeyGenerationParameters) obj;

			if(this.N != other.N) {
				return false;
			}

			if(this.bufferLenBits != other.bufferLenBits) {
				return false;
			}

			if(this.bufferLenTrits != other.bufferLenTrits) {
				return false;
			}

			if(this.c != other.c) {
				return false;
			}

			if(this.db != other.db) {
				return false;
			}

			if(this.df != other.df) {
				return false;
			}

			if(this.df1 != other.df1) {
				return false;
			}

			if(this.df2 != other.df2) {
				return false;
			}

			if(this.df3 != other.df3) {
				return false;
			}

			if(this.dg != other.dg) {
				return false;
			}

			if(this.dm0 != other.dm0) {
				return false;
			}

			if(this.dr != other.dr) {
				return false;
			}

			if(this.dr1 != other.dr1) {
				return false;
			}

			if(this.dr2 != other.dr2) {
				return false;
			}

			if(this.dr3 != other.dr3) {
				return false;
			}

			if(this.fastFp != other.fastFp) {
				return false;
			}

			if(this.hashAlg == null) {
				if(other.hashAlg != null) {
					return false;
				}
			} else if(!this.hashAlg.AlgorithmName.Equals(other.hashAlg.AlgorithmName)) {
				return false;
			}

			if(this.hashSeed != other.hashSeed) {
				return false;
			}

			if(this.llen != other.llen) {
				return false;
			}

			if(this.maxMsgLenBytes != other.maxMsgLenBytes) {
				return false;
			}

			if(this.minCallsMask != other.minCallsMask) {
				return false;
			}

			if(this.minCallsR != other.minCallsR) {
				return false;
			}

			if(!Equals(this.oid, other.oid)) {
				return false;
			}

			if(this.pkLen != other.pkLen) {
				return false;
			}

			if(this.polyType != other.polyType) {
				return false;
			}

			if(this.q != other.q) {
				return false;
			}

			if(this.sparse != other.sparse) {
				return false;
			}

			return true;
		}

		public override string ToString() {
			StringBuilder output = new StringBuilder("EncryptionParameters(N=" + this.N + " q=" + this.q);

			if(this.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE) {
				output.Append(" polyType=SIMPLE df=" + this.df);
			} else {
				output.Append(" polyType=PRODUCT df1=" + this.df1 + " df2=" + this.df2 + " df3=" + this.df3);
			}

			output.Append(" dm0=" + this.dm0 + " db=" + this.db + " c=" + this.c + " minCallsR=" + this.minCallsR + " minCallsMask=" + this.minCallsMask + " hashSeed=" + this.hashSeed + " hashAlg=" + this.hashAlg + " oid=" + ArraysExtensions.ToString(this.oid.Span.ToArray()) + " sparse=" + this.sparse + ")");

			return output.ToString();
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
					if((this.hashAlg != null) && this.hashAlg is IDisposable dispo) {
						dispo.Dispose();
					}

					this.oid.Dispose();

				} finally {
					this.IsDisposed = true;
				}
			}
		}

		~NTRUEncryptionKeyGenerationParameters() {
			this.Dispose(false);
		}

	#endregion

	}

}
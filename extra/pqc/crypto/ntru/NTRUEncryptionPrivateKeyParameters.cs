using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Microsoft.IO;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	/// <summary>
	///     A NtruEncrypt private key is essentially a polynomial named <code>f</code>
	///     which takes different forms depending on whether product-form polynomials are used,
	///     and on <code>fastP</code>
	///     <br>
	///         The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
	/// </summary>
	public class NTRUEncryptionPrivateKeyParameters : NTRUEncryptionKeyParameters {
		public IntegerPolynomial fp;
		public IntegerPolynomial h;
		public IPolynomial       t;

		/// <summary>
		///     Constructs a new private key from a polynomial
		/// </summary>
		/// <param name="h"> the public polynomial for the key. </param>
		/// <param name="t">
		///     the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>;
		///     otherwise, <code>f=t</code>
		/// </param>
		/// <param name="fp">     the inverse of <code>f</code> </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		public NTRUEncryptionPrivateKeyParameters(IntegerPolynomial h, IPolynomial t, IntegerPolynomial fp, NTRUEncryptionParameters @params) : base(true, @params) {

			this.h  = h;
			this.t  = t;
			this.fp = fp;
		}

		/// <summary>
		///     Converts a byte array to a polynomial <code>f</code> and constructs a new private key
		/// </summary>
		/// <param name="b">      an encoded polynomial </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= # getEncoded
		/// (
		/// )
		/// </seealso>
		public NTRUEncryptionPrivateKeyParameters(SafeArrayHandle b, NTRUEncryptionParameters @params) : this((RecyclableMemoryStream) new RecyclableMemoryStreamManager().GetStream("input", b.Bytes, b.Offset, b.Length), @params) {
		}

		/// <summary>
		///     Reads a polynomial <code>f</code> from an input stream and constructs a new private key
		/// </summary>
		/// <param name="is">     an input stream </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= # writeTo( OutputStream
		/// )
		/// </seealso>
		public NTRUEncryptionPrivateKeyParameters(RecyclableMemoryStream KeyStream, NTRUEncryptionParameters @params) : base(true, @params) {

			if(@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT) {
				int N          = @params.N;
				int df1        = @params.df1;
				int df2        = @params.df2;
				int df3Ones    = @params.df3;
				int df3NegOnes = @params.fastFp ? @params.df3 : @params.df3 - 1;
				this.h = IntegerPolynomial.fromBinary(KeyStream, @params.N, @params.q);
				this.t = ProductFormPolynomial.fromBinary(KeyStream, N, df1, df2, df3Ones, df3NegOnes);
			} else {
				this.h = IntegerPolynomial.fromBinary(KeyStream, @params.N, @params.q);
				IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(KeyStream, @params.N);

				if(@params.sparse) {
					this.t = new SparseTernaryPolynomial(fInt);
				} else {
					this.t = new DenseTernaryPolynomial(fInt);
				}
			}

			this.init();
		}

		/// <summary>
		///     Converts the key to a byte array
		/// </summary>
		/// <returns> the encoded key </returns>
		/// <seealso cref= # NTRUEncryptionPrivateKeyParameters( ArrayWrapper, NTRUEncryptionParameters
		/// )
		/// </seealso>
		public virtual SafeArrayHandle Encoded {
			get {
				SafeArrayHandle res = null;
				using(SafeArrayHandle hBytes = this.h.toBinary(this.@params.q)) {
					SafeArrayHandle tBytes;

					if(this.t is ProductFormPolynomial) {
						tBytes = ((ProductFormPolynomial) this.t).toBinary();
					} else {
						tBytes = this.t.toIntegerPolynomial().toBinary3Tight();
					}

					res = ByteArray.Create(hBytes.Length + tBytes.Length);

					res.Entry.CopyFrom(hBytes.Entry, 0, 0, hBytes.Length);
					res.Entry.CopyFrom(tBytes.Entry, 0, hBytes.Length, tBytes.Length);

					hBytes.Dispose();
				}

				return res;
			}
		}

		/// <summary>
		///     Initializes <code>fp</code> from t.
		/// </summary>
		private void init() {
			if(this.@params.fastFp) {
				this.fp           = new IntegerPolynomial(this.@params.N);
				this.fp.coeffs[0] = 1;
			} else {
				this.fp = this.t.toIntegerPolynomial().invertF3();
			}
		}

		/// <summary>
		///     Writes the key to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		/// <seealso cref= # NTRUEncryptionPrivateKeyParameters( InputStream, NTRUEncryptionParameters
		/// )
		/// </seealso>
		public virtual void writeTo(Stream os) {
			os.Write(this.Encoded.Bytes, this.Encoded.Offset, this.Encoded.Length);
		}

		public override int GetHashCode() {
			const int prime  = 31;
			int       result = 1;
			result = (prime * result) + (this.@params == null ? 0 : this.@params.GetHashCode());
			result = (prime * result) + (this.t       == null ? 0 : this.t.GetHashCode());
			result = (prime * result) + (this.h       == null ? 0 : this.h.GetHashCode());

			return result;
		}

		public override bool Equals(object obj) {
			if(this == obj) {
				return true;
			}

			if(obj == null) {
				return false;
			}

			if(!(obj is NTRUEncryptionPrivateKeyParameters)) {
				return false;
			}

			NTRUEncryptionPrivateKeyParameters other = (NTRUEncryptionPrivateKeyParameters) obj;

			if(this.@params == null) {
				if(other.@params != null) {
					return false;
				}
			} else if(!this.@params.Equals(other.@params)) {
				return false;
			}

			if(this.t == null) {
				if(other.t != null) {
					return false;
				}
			} else if(!this.t.Equals(other.t)) {
				return false;
			}

			if(!this.h.Equals(other.h)) {
				return false;
			}

			return true;
		}
	}
}
using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.ntru {

	/// <summary>
	///     A NtruEncrypt public key is essentially a polynomial named <code>h</code>.
	/// </summary>
	public class NTRUEncryptionPublicKeyParameters : NTRUEncryptionKeyParameters {
		public IntegerPolynomial h;

		/// <summary>
		///     Constructs a new public key from a polynomial
		/// </summary>
		/// <param name="h">      the polynomial <code>h</code> which determines the key </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		public NTRUEncryptionPublicKeyParameters(IntegerPolynomial h, NTRUEncryptionParameters @params) : base(false, @params) {

			this.h = h;
		}

		/// <summary>
		///     Converts a byte array to a polynomial <code>h</code> and constructs a new public key
		/// </summary>
		/// <param name="b">      an encoded polynomial </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= # Encoded
		/// </seealso>
		public NTRUEncryptionPublicKeyParameters(IByteArray b, NTRUEncryptionParameters @params) : base(false, @params) {

			this.h = IntegerPolynomial.fromBinary(b, @params.N, @params.q);
		}

		/// <summary>
		///     Reads a polynomial <code>h</code> from an input stream and constructs a new public key
		/// </summary>
		/// <param name="is">     an input stream </param>
		/// <param name="params"> the NtruEncrypt parameters to use </param>
		/// <seealso cref= # writeTo( OutputStream
		/// )
		/// </seealso>
		public NTRUEncryptionPublicKeyParameters(Stream @is, NTRUEncryptionParameters @params) : base(false, @params) {

			this.h = IntegerPolynomial.fromBinary(@is, @params.N, @params.q);
		}

		/// <summary>
		///     Converts the key to a byte array
		/// </summary>
		/// <returns> the encoded key </returns>
		/// <seealso cref= # NTRUEncryptionPublicKeyParameters( IByteArray, NTRUEncryptionParameters
		/// )
		/// </seealso>
		public virtual IByteArray Encoded => this.h.toBinary(this.@params.q);

		/// <summary>
		///     Writes the key to an output stream
		/// </summary>
		/// <param name="os"> an output stream </param>
		/// <exception cref="IOException"> </exception>
		/// <seealso cref= # NTRUEncryptionPublicKeyParameters( InputStream, NTRUEncryptionParameters
		/// )
		/// </seealso>
		public virtual void writeTo(Stream os) {
			os.Write(this.Encoded.Bytes, this.Encoded.Offset, this.Encoded.Length);
		}

		public override int GetHashCode() {
			const int prime  = 31;
			int       result = 1;
			result = (prime * result) + (this.h       == null ? 0 : this.h.GetHashCode());
			result = (prime * result) + (this.@params == null ? 0 : this.@params.GetHashCode());

			return result;
		}

		public override bool Equals(object obj) {
			if(this == obj) {
				return true;
			}

			if(obj == null) {
				return false;
			}

			if(!(obj is NTRUEncryptionPublicKeyParameters)) {
				return false;
			}

			NTRUEncryptionPublicKeyParameters other = (NTRUEncryptionPublicKeyParameters) obj;

			if(this.h == null) {
				if(other.h != null) {
					return false;
				}
			} else if(!this.h.Equals(other.h)) {
				return false;
			}

			if(this.@params == null) {
				if(other.@params != null) {
					return false;
				}
			} else if(!this.@params.Equals(other.@params)) {
				return false;
			}

			return true;
		}
	}
}
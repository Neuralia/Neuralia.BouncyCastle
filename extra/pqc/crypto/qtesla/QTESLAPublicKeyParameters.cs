using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Serialization;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {
	/// <summary>
	///     qTESLA public key
	/// </summary>
	public sealed class QTESLAPublicKeyParameters : AsymmetricKeyParameter {

		/// <summary>
		///     Text of the qTESLA Public Key
		/// </summary>
		private readonly sbyte[] publicKey;

		/// <summary>
		///     qTESLA Security Category
		/// </summary>
		private readonly QTESLASecurityCategory.SecurityCategories securityCategory;

		/// <summary>
		///     Base constructor.
		/// </summary>
		/// <param name="securityCategory"> the security category for the passed in public key data. </param>
		/// <param name="publicKey"> the public key data. </param>
		public QTESLAPublicKeyParameters(QTESLASecurityCategory.SecurityCategories securityCategory, sbyte[] publicKey) : base(false) {

			if(publicKey.Length != QTESLASecurityCategory.getPublicSize(securityCategory)) {
				throw new ArgumentException("invalid key size for security category");
			}

			this.securityCategory = securityCategory;
			this.publicKey        = ArraysExtensions.Clone(publicKey);

		}

		/// <summary>
		///     Return the security category for this key.
		/// </summary>
		/// <returns> the key's security category. </returns>
		public QTESLASecurityCategory.SecurityCategories SecurityCategory => this.securityCategory;

		/// <summary>
		///     Return the key's public value.
		/// </summary>
		/// <returns> key public data. </returns>
		public sbyte[] PublicData => ArraysExtensions.Clone(this.publicKey);

		public IByteArray Dehydrate() {
			IDataDehydrator dehydrator = DataSerializationFactory.CreateDehydrator();

			dehydrator.Write((byte) this.securityCategory);
			dehydrator.WriteNonNullable((byte[]) (Array) this.publicKey);

			return dehydrator.ToArray();
		}

		public static QTESLAPublicKeyParameters Rehydrate(IByteArray data) {
			IDataRehydrator rehydrator = DataSerializationFactory.CreateRehydrator(data);

			QTESLASecurityCategory.SecurityCategories securityCategory = (QTESLASecurityCategory.SecurityCategories) rehydrator.ReadByte();
			IByteArray                                publicKey        = rehydrator.ReadNonNullableArray();

			var results = new QTESLAPublicKeyParameters(securityCategory, (sbyte[]) (Array) publicKey.ToExactByteArrayCopy());
			
			publicKey.Return();

			return results;
		}
	}

}
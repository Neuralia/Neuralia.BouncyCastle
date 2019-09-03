using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Serialization;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {

	/// <summary>
	///     qTESLA private key
	/// </summary>
	public sealed class QTESLAPrivateKeyParameters : AsymmetricKeyParameter {

		/// <summary>
		///     Text of the qTESLA Private Key
		/// </summary>
		private readonly sbyte[] privateKey;

		/// <summary>
		///     qTESLA Security Category (From 4 To 8)
		/// </summary>
		private readonly QTESLASecurityCategory.SecurityCategories securityCategory;

		/// <summary>
		///     Base constructor.
		/// </summary>
		/// <param name="securityCategory"> the security category for the passed in public key data. </param>
		/// <param name="privateKey"> the private key data. </param>
		public QTESLAPrivateKeyParameters(QTESLASecurityCategory.SecurityCategories securityCategory, sbyte[] privateKey) : base(true) {

			if(privateKey.Length != QTESLASecurityCategory.getPrivateSize(securityCategory)) {
				throw new ArgumentException("invalid key size for security category");
			}

			this.securityCategory = securityCategory;
			this.privateKey       = ArraysExtensions.Clone(privateKey);
		}

		/// <summary>
		///     Return the security category for this key.
		/// </summary>
		/// <returns> the key's security category. </returns>
		public QTESLASecurityCategory.SecurityCategories SecurityCategory => this.securityCategory;

		/// <summary>
		///     Return the key's secret value.
		/// </summary>
		/// <returns> key private data. </returns>
		public sbyte[] Secret => ArraysExtensions.Clone(this.privateKey);

		public IByteArray Dehydrate() {
			IDataDehydrator dehydrator = DataSerializationFactory.CreateDehydrator();

			dehydrator.Write((byte) this.securityCategory);
			dehydrator.WriteNonNullable((byte[]) (Array) this.privateKey);

			return dehydrator.ToArray();
		}

		public static QTESLAPrivateKeyParameters Rehydrate(IByteArray data) {
			IDataRehydrator rehydrator = DataSerializationFactory.CreateRehydrator(data);

			QTESLASecurityCategory.SecurityCategories securityCategory = (QTESLASecurityCategory.SecurityCategories) rehydrator.ReadByte();
			IByteArray                                privateKey       = rehydrator.ReadNonNullableArray();

			var results = new QTESLAPrivateKeyParameters(securityCategory, (sbyte[]) (Array) privateKey.ToExactByteArrayCopy());
			
			privateKey.Return();

			return results;
		}
	}

}
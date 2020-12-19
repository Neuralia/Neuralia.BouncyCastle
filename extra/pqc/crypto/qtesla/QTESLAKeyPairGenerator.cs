using System;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {

	/// <summary>
	///     Key-pair generator for qTESLA keys.
	/// </summary>
	public sealed class QTESLAKeyPairGenerator {
		private SecureRandom secureRandom;

		/// <summary>
		///     qTESLA Security Category
		/// </summary>
		private QTESLASecurityCategory.SecurityCategories securityCategory;

		/// <summary>
		///     Initialize the generator with a security category and a source of randomness.
		/// </summary>
		/// <param name="param"> a <seealso cref="QTESLAKeyGenerationParameters" /> object. </param>
		public void init(KeyGenerationParameters param) {
			QTESLAKeyGenerationParameters parameters = (QTESLAKeyGenerationParameters) param;

			this.secureRandom     = parameters.Random;
			this.securityCategory = parameters.SecurityCategory;
		}

		/// <summary>
		///     Generate a key-pair.
		/// </summary>
		/// <returns> a matching key-pair consisting of (QTESLAPublicKeyParameters, QTESLAPrivateKeyParameters). </returns>
		public AsymmetricCipherKeyPair generateKeyPair() {
			sbyte[] privateKey = this.allocatePrivate(this.securityCategory);
			sbyte[] publicKey  = this.allocatePublic(this.securityCategory);

			switch(this.securityCategory) {
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_I:
					QTESLA.generateKeyPairI(publicKey, privateKey, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_III:
					QTESLA.generateKeyPairIII(publicKey, privateKey, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_V:
					QTESLA.generateKeyPairV(publicKey, privateKey, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.HEURISTIC_V_SIZE:
					throw new NotImplementedException();
					//QTESLA.generateKeyPairVSize(publicKey, privateKey, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.PROVABLY_SECURE_I:
					QTESLA.generateKeyPairIP(publicKey, privateKey, this.secureRandom);

					break;
				case QTESLASecurityCategory.SecurityCategories.PROVABLY_SECURE_III:
					QTESLA.generateKeyPairIIIP(publicKey, privateKey, this.secureRandom);

					break;
				default:

					throw new ArgumentException("unknown security category: " + this.securityCategory);
			}

			return new AsymmetricCipherKeyPair(new QTESLAPublicKeyParameters(this.securityCategory, publicKey), new QTESLAPrivateKeyParameters(this.securityCategory, privateKey));
		}

		private sbyte[] allocatePrivate(QTESLASecurityCategory.SecurityCategories securityCategory) {
			return new sbyte[QTESLASecurityCategory.getPrivateSize(securityCategory)];
		}

		private sbyte[] allocatePublic(QTESLASecurityCategory.SecurityCategories securityCategory) {
			return new sbyte[QTESLASecurityCategory.getPublicSize(securityCategory)];
		}
	}

}


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {

	/// <summary>
	///     qTESLA key-pair generation parameters.
	/// </summary>
	public class QTESLAKeyGenerationParameters : KeyGenerationParameters {

		/// <summary>
		///     Base constructor - provide the qTESLA security category and a source of randomness.
		/// </summary>
		/// <param name="securityCategory"> the security category to generate the parameters for. </param>
		/// <param name="random">           the random byte source. </param>
		public QTESLAKeyGenerationParameters(QTESLASecurityCategory.SecurityCategories securityCategory, SecureRandom random) : base(random, -1) {

			QTESLASecurityCategory.getPrivateSize(securityCategory); // check the category is valid

			this.SecurityCategory = securityCategory;
		}

		/// <summary>
		///     Return the security category for these parameters.
		/// </summary>
		/// <returns> the security category for keys generated using these parameters. </returns>
		public virtual QTESLASecurityCategory.SecurityCategories SecurityCategory { get; }
	}

}
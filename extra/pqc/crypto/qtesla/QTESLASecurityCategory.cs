using System;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {
	/// <summary>
	///     The qTESLA security categories.
	/// </summary>
	public class QTESLASecurityCategory {
		public enum SecurityCategories : byte {
			HEURISTIC_I         = 0,
			HEURISTIC_III = 1,
			HEURISTIC_V = 2,
			HEURISTIC_V_SIZE = 3,
			PROVABLY_SECURE_I   = 4,
			PROVABLY_SECURE_III = 5
		}

		private QTESLASecurityCategory() {
		}

		internal static void validate(SecurityCategories securityCategory) {
			switch(securityCategory) {
				case SecurityCategories.HEURISTIC_I:
				case SecurityCategories.HEURISTIC_III:
				case SecurityCategories.HEURISTIC_V:
				case SecurityCategories.HEURISTIC_V_SIZE:
				case SecurityCategories.PROVABLY_SECURE_I:
				case SecurityCategories.PROVABLY_SECURE_III:
					break;
				default:

					throw new ArgumentException("unknown security category: " + securityCategory);
			}
		}

		internal static int getPrivateSize(SecurityCategories securityCategory) {
			switch(securityCategory) {
				case SecurityCategories.HEURISTIC_I:

					return Polynomial.PRIVATE_KEY_I;
				case SecurityCategories.HEURISTIC_III:

					return Polynomial.PRIVATE_KEY_III;
				
				case SecurityCategories.HEURISTIC_V:

					return Polynomial.PRIVATE_KEY_V;
				case SecurityCategories.HEURISTIC_V_SIZE:

					return Polynomial.PRIVATE_KEY_V_SIZE;
				case SecurityCategories.PROVABLY_SECURE_I:

					return Polynomial.PRIVATE_KEY_I_P;
				case SecurityCategories.PROVABLY_SECURE_III:

					return Polynomial.PRIVATE_KEY_III_P;
				default:

					throw new ArgumentException("unknown security category: " + securityCategory);
			}
		}

		internal static int getPublicSize(SecurityCategories securityCategory) {
			switch(securityCategory) {
				case SecurityCategories.HEURISTIC_I:

					return Polynomial.PUBLIC_KEY_I;
				case SecurityCategories.HEURISTIC_III:

					return Polynomial.PUBLIC_KEY_III_SPEED;
				case SecurityCategories.HEURISTIC_V:

					return Polynomial.PUBLIC_KEY_V;
				case SecurityCategories.HEURISTIC_V_SIZE:

					return Polynomial.PUBLIC_KEY_V_SIZE;
				case SecurityCategories.PROVABLY_SECURE_I:

					return Polynomial.PUBLIC_KEY_I_P;
				case SecurityCategories.PROVABLY_SECURE_III:

					return Polynomial.PUBLIC_KEY_III_P;
				default:

					throw new ArgumentException("unknown security category: " + securityCategory);
			}
		}

		internal static int getSignatureSize(SecurityCategories securityCategory) {
			switch(securityCategory) {
				case SecurityCategories.HEURISTIC_I:

					return Polynomial.SIGNATURE_I;
				case SecurityCategories.HEURISTIC_III:

					return Polynomial.SIGNATURE_III;
				case SecurityCategories.HEURISTIC_V:

					return Polynomial.SIGNATURE_V;
				case SecurityCategories.HEURISTIC_V_SIZE:

					return Polynomial.SIGNATURE_V_SIZE;
				case SecurityCategories.PROVABLY_SECURE_I:

					return Polynomial.SIGNATURE_I_P;
				case SecurityCategories.PROVABLY_SECURE_III:

					return Polynomial.SIGNATURE_III_P;
				default:

					throw new ArgumentException("unknown security category: " + securityCategory);
			}
		}

		/// <summary>
		///     Return a standard name for the security category.
		/// </summary>
		/// <param name="securityCategory"> the category of interest. </param>
		/// <returns> the name for the category. </returns>
		public static string getName(SecurityCategories securityCategory) {
			switch(securityCategory) {
				case SecurityCategories.HEURISTIC_I:

					return "qTESLA-I";
				case SecurityCategories.HEURISTIC_III:

					return "qTESLA-III";
				case SecurityCategories.HEURISTIC_V:

					return "qTESLA-V";
				case SecurityCategories.HEURISTIC_V_SIZE:

					return "qTESLA-V-size";
				case SecurityCategories.PROVABLY_SECURE_I:

					return "qTESLA-p-I";
				case SecurityCategories.PROVABLY_SECURE_III:

					return "qTESLA-p-III";
				default:

					throw new ArgumentException("unknown security category: " + securityCategory);
			}
		}
	}

}
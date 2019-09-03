using System;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Crypto.Prng;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {
	internal class Pack {

		/// <summary>
		///     *****************************************************************************************************************************************************
		///     Description:	Encode Private Key for Heuristic qTESLA Security Category-1
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">
		///     Starting Point of the Kappa-Bit Seed
		/// </param>
		/// <returns>
		///     none
		///     ******************************************************************************************************************************************************
		/// </returns>
		public static void encodePrivateKeyI(sbyte[] privateKey, int[] secretPolynomial, int[] errorPolynomial, sbyte[] seed, int seedOffset) {

			int j = 0;

			for(int i = 0; i < Parameter.N_I; i += 8) {

				privateKey[j + 0] = (sbyte) secretPolynomial[i + 0];
				privateKey[j + 1] = (sbyte) (((secretPolynomial[i + 0] >> 8) & 0x01) | (secretPolynomial[i + 1] << 1));
				privateKey[j + 2] = (sbyte) (((secretPolynomial[i + 1] >> 7) & 0x03) | (secretPolynomial[i + 2] << 2));
				privateKey[j + 3] = (sbyte) (((secretPolynomial[i + 2] >> 6) & 0x07) | (secretPolynomial[i + 3] << 3));
				privateKey[j + 4] = (sbyte) (((secretPolynomial[i + 3] >> 5) & 0x0F) | (secretPolynomial[i + 4] << 4));
				privateKey[j + 5] = (sbyte) (((secretPolynomial[i + 4] >> 4) & 0x1F) | (secretPolynomial[i + 5] << 5));
				privateKey[j + 6] = (sbyte) (((secretPolynomial[i + 5] >> 3) & 0x3F) | (secretPolynomial[i + 6] << 6));
				privateKey[j + 7] = (sbyte) (((secretPolynomial[i + 6] >> 2) & 0x7F) | (secretPolynomial[i + 7] << 7));
				privateKey[j + 8] = (sbyte) (secretPolynomial[i + 7] >> 1);

				j += 9;

			}

			for(int i = 0; i < Parameter.N_I; i += 8) {

				privateKey[j + 0] = (sbyte) errorPolynomial[i + 0];
				privateKey[j + 1] = (sbyte) (((errorPolynomial[i + 0] >> 8) & 0x01) | (errorPolynomial[i + 1] << 1));
				privateKey[j + 2] = (sbyte) (((errorPolynomial[i + 1] >> 7) & 0x03) | (errorPolynomial[i + 2] << 2));
				privateKey[j + 3] = (sbyte) (((errorPolynomial[i + 2] >> 6) & 0x07) | (errorPolynomial[i + 3] << 3));
				privateKey[j + 4] = (sbyte) (((errorPolynomial[i + 3] >> 5) & 0x0F) | (errorPolynomial[i + 4] << 4));
				privateKey[j + 5] = (sbyte) (((errorPolynomial[i + 4] >> 4) & 0x1F) | (errorPolynomial[i + 5] << 5));
				privateKey[j + 6] = (sbyte) (((errorPolynomial[i + 5] >> 3) & 0x3F) | (errorPolynomial[i + 6] << 6));
				privateKey[j + 7] = (sbyte) (((errorPolynomial[i + 6] >> 2) & 0x7F) | (errorPolynomial[i + 7] << 7));
				privateKey[j + 8] = (sbyte) (errorPolynomial[i + 7] >> 1);

				j += 9;

			}

			Buffer.BlockCopy(seed, seedOffset, privateKey, (Parameter.N_I * Parameter.S_BIT_I * 2) / Const.BYTE_SIZE, Polynomial.SEED * 2);

		}

		/// <summary>
		///     *********************************************************************************************************************************************************************************
		///     Description:	Encode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">
		///     Starting Point of the Kappa-Bit Seed
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************************************************************************
		/// </returns>
		public static void encodePrivateKeyIII(sbyte[] privateKey, int[] secretPolynomial, int[] errorPolynomial, sbyte[] seed, int seedOffset) {

			int j = 0;

			for(int i = 0; i < Parameter.N_III; i += 8) {

				privateKey[j + 0] = (sbyte) secretPolynomial[i + 0];
				privateKey[j + 1] = (sbyte) (((secretPolynomial[i + 0] >> 8) & 0x01) | (secretPolynomial[i + 1] << 1));
				privateKey[j + 2] = (sbyte) (((secretPolynomial[i + 1] >> 7) & 0x03) | (secretPolynomial[i + 2] << 2));
				privateKey[j + 3] = (sbyte) (((secretPolynomial[i + 2] >> 6) & 0x07) | (secretPolynomial[i + 3] << 3));
				privateKey[j + 4] = (sbyte) (((secretPolynomial[i + 3] >> 5) & 0x0F) | (secretPolynomial[i + 4] << 4));
				privateKey[j + 5] = (sbyte) (((secretPolynomial[i + 4] >> 4) & 0x1F) | (secretPolynomial[i + 5] << 5));
				privateKey[j + 6] = (sbyte) (((secretPolynomial[i + 5] >> 3) & 0x3F) | (secretPolynomial[i + 6] << 6));
				privateKey[j + 7] = (sbyte) (((secretPolynomial[i + 6] >> 2) & 0x7F) | (secretPolynomial[i + 7] << 7));
				privateKey[j + 8] = (sbyte) (secretPolynomial[i + 7] >> 1);

				j += 9;

			}

			for(int i = 0; i < Parameter.N_III; i += 8) {

				privateKey[j + 0] = (sbyte) errorPolynomial[i + 0];
				privateKey[j + 1] = (sbyte) (((errorPolynomial[i + 0] >> 8) & 0x01) | (errorPolynomial[i + 1] << 1));
				privateKey[j + 2] = (sbyte) (((errorPolynomial[i + 1] >> 7) & 0x03) | (errorPolynomial[i + 2] << 2));
				privateKey[j + 3] = (sbyte) (((errorPolynomial[i + 2] >> 6) & 0x07) | (errorPolynomial[i + 3] << 3));
				privateKey[j + 4] = (sbyte) (((errorPolynomial[i + 3] >> 5) & 0x0F) | (errorPolynomial[i + 4] << 4));
				privateKey[j + 5] = (sbyte) (((errorPolynomial[i + 4] >> 4) & 0x1F) | (errorPolynomial[i + 5] << 5));
				privateKey[j + 6] = (sbyte) (((errorPolynomial[i + 5] >> 3) & 0x3F) | (errorPolynomial[i + 6] << 6));
				privateKey[j + 7] = (sbyte) (((errorPolynomial[i + 6] >> 2) & 0x7F) | (errorPolynomial[i + 7] << 7));
				privateKey[j + 8] = (sbyte) (errorPolynomial[i + 7] >> 1);

				j += 9;

			}

			Buffer.BlockCopy(seed, seedOffset, privateKey, (Parameter.N_III * Parameter.S_BIT_III * 2) / Const.BYTE_SIZE, Polynomial.SEED * 2);

		}

		/// <summary>
		///     *********************************************************************************************************************************************************************************
		///     Description:	Encode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">
		///     Starting Point of the Kappa-Bit Seed
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************************************************************************
		/// </returns>
		public static void encodePrivateKeyV(sbyte[] privateKey, int[] secretPolynomial, int[] errorPolynomial, sbyte[] seed, int seedOffset) {

			int j = 0;

			for(int i = 0; i < Parameter.N_V; i += 8) {

				privateKey[j + 0] = (sbyte) secretPolynomial[i + 0];
				privateKey[j + 1] = (sbyte) (((secretPolynomial[i + 0] >> 8) & 0x01) | (secretPolynomial[i + 1] << 1));
				privateKey[j + 2] = (sbyte) (((secretPolynomial[i + 1] >> 7) & 0x03) | (secretPolynomial[i + 2] << 2));
				privateKey[j + 3] = (sbyte) (((secretPolynomial[i + 2] >> 6) & 0x07) | (secretPolynomial[i + 3] << 3));
				privateKey[j + 4] = (sbyte) (((secretPolynomial[i + 3] >> 5) & 0x0F) | (secretPolynomial[i + 4] << 4));
				privateKey[j + 5] = (sbyte) (((secretPolynomial[i + 4] >> 4) & 0x1F) | (secretPolynomial[i + 5] << 5));
				privateKey[j + 6] = (sbyte) (((secretPolynomial[i + 5] >> 3) & 0x3F) | (secretPolynomial[i + 6] << 6));
				privateKey[j + 7] = (sbyte) (((secretPolynomial[i + 6] >> 2) & 0x7F) | (secretPolynomial[i + 7] << 7));
				privateKey[j + 8] = (sbyte) (secretPolynomial[i + 7] >> 1);

				j += 9;

			}

			for(int i = 0; i < Parameter.N_V; i += 8) {

				privateKey[j + 0] = (sbyte) errorPolynomial[i + 0];
				privateKey[j + 1] = (sbyte) (((errorPolynomial[i + 0] >> 8) & 0x01) | (errorPolynomial[i + 1] << 1));
				privateKey[j + 2] = (sbyte) (((errorPolynomial[i + 1] >> 7) & 0x03) | (errorPolynomial[i + 2] << 2));
				privateKey[j + 3] = (sbyte) (((errorPolynomial[i + 2] >> 6) & 0x07) | (errorPolynomial[i + 3] << 3));
				privateKey[j + 4] = (sbyte) (((errorPolynomial[i + 3] >> 5) & 0x0F) | (errorPolynomial[i + 4] << 4));
				privateKey[j + 5] = (sbyte) (((errorPolynomial[i + 4] >> 4) & 0x1F) | (errorPolynomial[i + 5] << 5));
				privateKey[j + 6] = (sbyte) (((errorPolynomial[i + 5] >> 3) & 0x3F) | (errorPolynomial[i + 6] << 6));
				privateKey[j + 7] = (sbyte) (((errorPolynomial[i + 6] >> 2) & 0x7F) | (errorPolynomial[i + 7] << 7));
				privateKey[j + 8] = (sbyte) (errorPolynomial[i + 7] >> 1);

				j += 9;

			}

			Buffer.BlockCopy(seed, seedOffset, privateKey, (Parameter.N_V * Parameter.S_BIT_V * 2) / Const.BYTE_SIZE, Polynomial.SEED * 2);

		}

		/// <summary>
		///     *****************************************************************************************************************************
		///     Description:	Decode Private Key for Heuristic qTESLA Security Category-1
		/// </summary>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="privateKey">
		///     Private Key
		/// </param>
		/// <returns>
		///     none
		///     ******************************************************************************************************************************
		/// </returns>
		public static void decodePrivateKeyI(sbyte[] seed, short[] secretPolynomial, short[] errorPolynomial, sbyte[] privateKey) {

			int j = 0;
			int temporary = 0;

			for(int i = 0; i < Parameter.N_I; i += 8) {

				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0] = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				secretPolynomial[i + 0] |= (short) temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				secretPolynomial[i + 1] = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				secretPolynomial[i + 1] |= (short) temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				secretPolynomial[i + 2] = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				secretPolynomial[i + 2] |= (short) temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				secretPolynomial[i + 3] = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				secretPolynomial[i + 3] |= (short) temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				secretPolynomial[i + 4] = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				secretPolynomial[i + 4] |= (short) temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				secretPolynomial[i + 5] = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				secretPolynomial[i + 5] |= (short) temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				secretPolynomial[i + 6] = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				secretPolynomial[i + 6] |= (short) temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				secretPolynomial[i + 7] = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				secretPolynomial[i + 7] |= (short) temporary;

				j += 9;

			}

			for(int i = 0; i < Parameter.N_I; i += 8) {

				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0] = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				errorPolynomial[i + 0] |= (short) temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				errorPolynomial[i + 1] = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				errorPolynomial[i + 1] |= (short) temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				errorPolynomial[i + 2] = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				errorPolynomial[i + 2] |= (short) temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				errorPolynomial[i + 3] = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				errorPolynomial[i + 3] |= (short) temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				errorPolynomial[i + 4] = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				errorPolynomial[i + 4] |= (short) temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				errorPolynomial[i + 5] = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				errorPolynomial[i + 5] |= (short) temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				errorPolynomial[i + 6] = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				errorPolynomial[i + 6] |= (short) temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				errorPolynomial[i + 7] = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				errorPolynomial[i + 7] |= (short) temporary;

				j += 9;

			}

			Buffer.BlockCopy(privateKey, (Parameter.N_I * Parameter.S_BIT_I * 2) / Const.BYTE_SIZE, seed, 0, Polynomial.SEED * 2);

		}

		/// <summary>
		///     ************************************************************************************************************************************
		///     Description:	Decode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="privateKey">
		///     Private Key
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************
		/// </returns>
		public static void decodePrivateKeyIII(sbyte[] seed, short[] secretPolynomial, short[] errorPolynomial, sbyte[] privateKey) {

			int j = 0;
			int temporary = 0;

			for(int i = 0; i < Parameter.N_III; i += 8) {

				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0] = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				secretPolynomial[i + 0] |= (short) temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				secretPolynomial[i + 1] = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				secretPolynomial[i + 1] |= (short) temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				secretPolynomial[i + 2] = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				secretPolynomial[i + 2] |= (short) temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				secretPolynomial[i + 3] = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				secretPolynomial[i + 3] |= (short) temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				secretPolynomial[i + 4] = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				secretPolynomial[i + 4] |= (short) temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				secretPolynomial[i + 5] = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				secretPolynomial[i + 5] |= (short) temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				secretPolynomial[i + 6] = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				secretPolynomial[i + 6] |= (short) temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				secretPolynomial[i + 7] = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				secretPolynomial[i + 7] |= (short) temporary;

				j += 9;

			}

			for(int i = 0; i < Parameter.N_III; i += 8) {

				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0] = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				errorPolynomial[i + 0] |= (short) temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				errorPolynomial[i + 1] = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				errorPolynomial[i + 1] |= (short) temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				errorPolynomial[i + 2] = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				errorPolynomial[i + 2] |= (short) temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				errorPolynomial[i + 3] = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				errorPolynomial[i + 3] |= (short) temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				errorPolynomial[i + 4] = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				errorPolynomial[i + 4] |= (short) temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				errorPolynomial[i + 5] = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				errorPolynomial[i + 5] |= (short) temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				errorPolynomial[i + 6] = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				errorPolynomial[i + 6] |= (short) temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				errorPolynomial[i + 7] = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				errorPolynomial[i + 7] |= (short) temporary;

				j += 9;

			}

			Buffer.BlockCopy(privateKey, (Parameter.N_III * Parameter.S_BIT_III * 2) / Const.BYTE_SIZE, seed, 0, Polynomial.SEED * 2);

		}

		/// <summary>
		///     ************************************************************************************************************************************
		///     Description:	Decode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="privateKey">
		///     Private Key
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************
		/// </returns>
		public static void decodePrivateKeyV(sbyte[] seed, short[] secretPolynomial, short[] errorPolynomial, sbyte[] privateKey) {

			int j = 0;
			int temporary = 0;

			for(int i = 0; i < Parameter.N_V; i += 8) {

				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0] = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				secretPolynomial[i + 0] |= (short) temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				secretPolynomial[i + 1] = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				secretPolynomial[i + 1] |= (short) temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				secretPolynomial[i + 2] = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				secretPolynomial[i + 2] |= (short) temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				secretPolynomial[i + 3] = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				secretPolynomial[i + 3] |= (short) temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				secretPolynomial[i + 4] = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				secretPolynomial[i + 4] |= (short) temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				secretPolynomial[i + 5] = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				secretPolynomial[i + 5] |= (short) temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				secretPolynomial[i + 6] = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				secretPolynomial[i + 6] |= (short) temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				secretPolynomial[i + 7] = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				secretPolynomial[i + 7] |= (short) temporary;

				j += 9;

			}

			for(int i = 0; i < Parameter.N_V; i += 8) {

				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0] = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				errorPolynomial[i + 0] |= (short) temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				errorPolynomial[i + 1] = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				errorPolynomial[i + 1] |= (short) temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				errorPolynomial[i + 2] = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				errorPolynomial[i + 2] |= (short) temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				errorPolynomial[i + 3] = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				errorPolynomial[i + 3] |= (short) temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				errorPolynomial[i + 4] = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				errorPolynomial[i + 4] |= (short) temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				errorPolynomial[i + 5] = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				errorPolynomial[i + 5] |= (short) temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				errorPolynomial[i + 6] = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				errorPolynomial[i + 6] |= (short) temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				errorPolynomial[i + 7] = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				errorPolynomial[i + 7] |= (short) temporary;

				j += 9;

			}

			Buffer.BlockCopy(privateKey, (Parameter.N_V * Parameter.S_BIT_V * 2) / Const.BYTE_SIZE, seed, 0, Polynomial.SEED * 2);

		}

		/// <summary>
		///     ******************************************************************************************************************************************************************
		///     Description:	Pack Private Key for Provably-Secure qTESLA Security Category-1 and Security Category-3
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">                Starting Point of the Kappa-Bit Seed </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="k">
		///     Number of Ring-Learning-With-Errors Samples
		/// </param>
		/// <returns>
		///     none
		///     *******************************************************************************************************************************************************************
		/// </returns>
		public static void packPrivateKey(sbyte[] privateKey, long[] secretPolynomial, long[] errorPolynomial, sbyte[] seed, int seedOffset, int n, int k) {

			for(int i = 0; i < n; i++) {
				privateKey[i] = (sbyte) secretPolynomial[i];
			}

			for(int j = 0; j < k; j++) {
				for(int i = 0; i < n; i++) {
					privateKey[n + j * n + i] = (sbyte) errorPolynomial[j * n + i];
				}
			}

			Buffer.BlockCopy(seed, seedOffset, privateKey, n + (k * n), Polynomial.SEED * 2);

		}

		/// <summary>
		///     ************************************************************************************************************************************************
		///     Description:	Encode Public Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="publicKeyInput">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="qLogarithm">
		///     q <= 2 ^ qLogartihm
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************************
		/// </returns>
		public static void encodePublicKey(sbyte[] publicKeyInput, int[] T, sbyte[] seedA, int seedAOffset, int n, int qLogarithm) {

			int j = 0;

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_I * Parameter.Q_LOGARITHM_I / Const.INT_SIZE); i += Parameter.Q_LOGARITHM_I) {
				pt[i   ] = (uint)(T[j] | (T[j+1] << 23));
				pt[i+ 1] = (uint)((T[j+ 1] >>  9) | (T[j+ 2] << 14)); pt[i+ 2] = (uint)((T[j+ 2] >> 18) | (T[j+ 3] <<  5) | (T[j+ 4] << 28));
				pt[i+ 3] = (uint)((T[j+ 4] >>  4) | (T[j+ 5] << 19));
				pt[i+ 4] = (uint)((T[j+ 5] >> 13) | (T[j+ 6] << 10)); pt[i+ 5] = (uint)((T[j+ 6] >> 22) | (T[j+ 7] <<  1) | (T[j+ 8] << 24));
				pt[i+ 6] = (uint)((T[j+ 8] >>  8) | (T[j+ 9] << 15)); pt[i+ 7] = (uint)((T[j+ 9] >> 17) | (T[j+10] <<  6) | (T[j+11] << 29));
				pt[i+ 8] = (uint)((T[j+11] >>  3) | (T[j+12] << 20));
				pt[i+ 9] = (uint)((T[j+12] >> 12) | (T[j+13] << 11)); pt[i+10] = (uint)((T[j+13] >> 21) | (T[j+14] <<  2) | (T[j+15] << 25));
				pt[i+11] = (uint)((T[j+15] >>  7) | (T[j+16] << 16)); pt[i+12] = (uint)((T[j+16] >> 16) | (T[j+17] <<  7) | (T[j+18] << 30));
				pt[i+13] = (uint)((T[j+18] >>  2) | (T[j+19] << 21));
				pt[i+14] = (uint)((T[j+19] >> 11) | (T[j+20] << 12)); pt[i+15] = (uint)((T[j+20] >> 20) | (T[j+21] <<  3) | (T[j+22] << 26));
				pt[i+16] = (uint)((T[j+22] >>  6) | (T[j+23] << 17)); pt[i+17] = (uint)((T[j+23] >> 15) | (T[j+24] <<  8) | (T[j+25] << 31));
				pt[i+18] = (uint)((T[j+25] >>  1) | (T[j+26] << 22));
				pt[i+19] = (uint)((T[j+26] >> 10) | (T[j+27] << 13)); pt[i+20] = (uint)((T[j+27] >> 19) | (T[j+28] <<  4) | (T[j+29] << 27));
				pt[i+21] = (uint)((T[j+29] >>  5) | (T[j+30] << 18));
				pt[i+22] = (uint)((T[j+30] >> 14) | (T[j+31] <<  9));
				j += Const.INT_SIZE;
			}

			Buffer.BlockCopy(seedA, seedAOffset, publicKeyInput, (n * qLogarithm) / Const.BYTE_SIZE, Polynomial.SEED);

		}

		/// <summary>
		///     ****************************************************************************************************************************************************
		///     Description:	Encode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="publicKeyInput">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">
		///     Starting Point of the Seed A
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************
		/// </returns>
		public static void encodePublicKeyIII(sbyte[] publicKeyInput, int[] T, sbyte[] seedA, int seedAOffset) {

			int j = 0;

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_III * Parameter.Q_LOGARITHM_III / Const.INT_SIZE); i += Parameter.Q_LOGARITHM_III) {
				pt[i + 0] = (uint) (T[j + 0] | (T[j + 1] << 24));
				pt[i + 1] = (uint) ((T[j + 1] >> 8) | (T[j + 2] << 16));
				pt[i + 2] = (uint) ((T[j + 2] >> 16) | (T[j + 3] << 8));
				pt[i + 3] = (uint) (T[j + 4] | (T[j + 5] << 24));
				pt[i + 4] = (uint) ((T[j + 5] >> 8) | (T[j + 6] << 16));
				pt[i + 5] = (uint) ((T[j + 6] >> 16) | (T[j + 7] << 8));
				pt[i + 6] = (uint) (T[j + 8] | (T[j + 9] << 24));
				pt[i + 7] = (uint) ((T[j + 9] >> 8) | (T[j + 10] << 16));
				pt[i + 8] = (uint) ((T[j + 10] >> 16) | (T[j + 11] << 8));
				pt[i + 9] = (uint) (T[j + 12] | (T[j + 13] << 24));
				pt[i + 10] = (uint) ((T[j + 13] >> 8) | (T[j + 14] << 16));
				pt[i + 11] = (uint) ((T[j + 14] >> 16) | (T[j + 15] << 8));
				pt[i + 12] = (uint) (T[j + 16] | (T[j + 17] << 24));
				pt[i + 13] = (uint) ((T[j + 17] >> 8) | (T[j + 18] << 16));
				pt[i + 14] = (uint) ((T[j + 18] >> 16) | (T[j + 19] << 8));
				pt[i + 15] = (uint) (T[j + 20] | (T[j + 21] << 24));
				pt[i + 16] = (uint) ((T[j + 21] >> 8) | (T[j + 22] << 16));
				pt[i + 17] = (uint) ((T[j + 22] >> 16) | (T[j + 23] << 8));
				pt[i + 18] = (uint) (T[j + 24] | (T[j + 25] << 24));
				pt[i + 19] = (uint) ((T[j + 25] >> 8) | (T[j + 26] << 16));
				pt[i + 20] = (uint) ((T[j + 26] >> 16) | (T[j + 27] << 8));
				pt[i + 21] = (uint) (T[j + 28] | (T[j + 29] << 24));
				pt[i + 22] = (uint) ((T[j + 29] >> 8) | (T[j + 30] << 16));
				pt[i + 23] = (uint) ((T[j + 30] >> 16) | (T[j + 31] << 8));

				j += Const.INT_SIZE;
			}

			Buffer.BlockCopy(seedA, seedAOffset, publicKeyInput, (Parameter.N_III * Parameter.Q_LOGARITHM_III) / Const.BYTE_SIZE, Polynomial.SEED);

		}

		/// <summary>
		///     ****************************************************************************************************************************************************
		///     Description:	Encode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="publicKeyInput">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">
		///     Starting Point of the Seed A
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************
		/// </returns>
		public static void encodePublicKeyV(sbyte[] publicKeyInput, int[] T, sbyte[] seedA, int seedAOffset) {

			int j = 0;

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_V * Parameter.Q_LOGARITHM_V / Const.INT_SIZE); i += Parameter.Q_LOGARITHM_V) {
				pt[i + 0] = (uint) (T[j + 0] | (T[j + 1] << 25));
				pt[i + 1] = (uint) ((T[j + 1] >> 7) | (T[j + 2] << 18));
				pt[i + 2] = (uint) ((T[j + 2] >> 14) | (T[j + 3] << 11));
				pt[i + 3] = (uint) ((T[j + 3] >> 21) | (T[j + 4] << 4) | (T[j + 5] << 29));
				pt[i + 4] = (uint) ((T[j + 5] >> 3) | (T[j + 6] << 22));
				pt[i + 5] = (uint) ((T[j + 6] >> 10) | (T[j + 7] << 15));
				pt[i + 6] = (uint) ((T[j + 7] >> 17) | (T[j + 8] << 8));
				pt[i + 7] = (uint) ((T[j + 8] >> 24) | (T[j + 9] << 1) | (T[j + 10] << 26));
				pt[i + 8] = (uint) ((T[j + 10] >> 6) | (T[j + 11] << 19));
				pt[i + 9] = (uint) ((T[j + 11] >> 13) | (T[j + 12] << 12));
				pt[i + 10] = (uint) ((T[j + 12] >> 20) | (T[j + 13] << 5) | (T[j + 14] << 30));
				pt[i + 11] = (uint) ((T[j + 14] >> 2) | (T[j + 15] << 23));
				pt[i + 12] = (uint) ((T[j + 15] >> 9) | (T[j + 16] << 16));
				pt[i + 13] = (uint) ((T[j + 16] >> 16) | (T[j + 17] << 9));
				pt[i + 14] = (uint) ((T[j + 17] >> 23) | (T[j + 18] << 2) | (T[j + 19] << 27));
				pt[i + 15] = (uint) ((T[j + 19] >> 5) | (T[j + 20] << 20));
				pt[i + 16] = (uint) ((T[j + 20] >> 12) | (T[j + 21] << 13));
				pt[i + 17] = (uint) ((T[j + 21] >> 19) | (T[j + 22] << 6) | (T[j + 23] << 31));
				pt[i + 18] = (uint) ((T[j + 23] >> 1) | (T[j + 24] << 24));
				pt[i + 19] = (uint) ((T[j + 24] >> 8) | (T[j + 25] << 17));
				pt[i + 20] = (uint) ((T[j + 25] >> 15) | (T[j + 26] << 10));
				pt[i + 21] = (uint) ((T[j + 26] >> 22) | (T[j + 27] << 3) | (T[j + 28] << 28));
				pt[i + 22] = (uint) ((T[j + 28] >> 4) | (T[j + 29] << 21));
				pt[i + 23] = (uint) ((T[j + 29] >> 11) | (T[j + 30] << 14));
				pt[i + 24] = (uint) ((T[j + 30] >> 18) | (T[j + 31] << 7));

				j += Const.INT_SIZE;
			}

			Buffer.BlockCopy(seedA, seedAOffset, publicKeyInput, (Parameter.N_V * Parameter.Q_LOGARITHM_V) / Const.BYTE_SIZE, Polynomial.SEED);

		}

		/// <summary>
		///     *****************************************************************************************************************************************************
		///     Description:	Encode Public Key for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="publicKeyInput">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">
		///     Starting Point of the Seed A
		/// </param>
		/// <returns>
		///     none
		///     ******************************************************************************************************************************************************
		/// </returns>
		public static void encodePublicKeyIP(sbyte[] publicKeyInput, long[] T, sbyte[] seedA, int seedAOffset) {

			int j = 0;

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Const.INT_SIZE); i += Parameter.Q_LOGARITHM_I_P) {
				pt[i] = (uint) (T[j] | (T[j + 1] << 29));
				pt[i + 1] = (uint) ((T[j + 1] >> 3) | (T[j + 2] << 26));
				pt[i + 2] = (uint) ((T[j + 2] >> 6) | (T[j + 3] << 23));
				pt[i + 3] = (uint) ((T[j + 3] >> 9) | (T[j + 4] << 20));
				pt[i + 4] = (uint) ((T[j + 4] >> 12) | (T[j + 5] << 17));
				pt[i + 5] = (uint) ((T[j + 5] >> 15) | (T[j + 6] << 14));
				pt[i + 6] = (uint) ((T[j + 6] >> 18) | (T[j + 7] << 11));
				pt[i + 7] = (uint) ((T[j + 7] >> 21) | (T[j + 8] << 8));
				pt[i + 8] = (uint) ((T[j + 8] >> 24) | (T[j + 9] << 5));
				pt[i + 9] = (uint) ((T[j + 9] >> 27) | (T[j + 10] << 2) | (T[j + 11] << 31));
				pt[i + 10] = (uint) ((T[j + 11] >> 1) | (T[j + 12] << 28));
				pt[i + 11] = (uint) ((T[j + 12] >> 4) | (T[j + 13] << 25));
				pt[i + 12] = (uint) ((T[j + 13] >> 7) | (T[j + 14] << 22));
				pt[i + 13] = (uint) ((T[j + 14] >> 10) | (T[j + 15] << 19));
				pt[i + 14] = (uint) ((T[j + 15] >> 13) | (T[j + 16] << 16));
				pt[i + 15] = (uint) ((T[j + 16] >> 16) | (T[j + 17] << 13));
				pt[i + 16] = (uint) ((T[j + 17] >> 19) | (T[j + 18] << 10));
				pt[i + 17] = (uint) ((T[j + 18] >> 22) | (T[j + 19] << 7));
				pt[i + 18] = (uint) ((T[j + 19] >> 25) | (T[j + 20] << 4));
				pt[i + 19] = (uint) ((T[j + 20] >> 28) | (T[j + 21] << 1) | (T[j + 22] << 30));
				pt[i + 20] = (uint) ((T[j + 22] >> 2) | (T[j + 23] << 27));
				pt[i + 21] = (uint) ((T[j + 23] >> 5) | (T[j + 24] << 24));
				pt[i + 22] = (uint) ((T[j + 24] >> 8) | (T[j + 25] << 21));
				pt[i + 23] = (uint) ((T[j + 25] >> 11) | (T[j + 26] << 18));
				pt[i + 24] = (uint) ((T[j + 26] >> 14) | (T[j + 27] << 15));
				pt[i + 25] = (uint) ((T[j + 27] >> 17) | (T[j + 28] << 12));
				pt[i + 26] = (uint) ((T[j + 28] >> 20) | (T[j + 29] << 9));
				pt[i + 27] = (uint) ((T[j + 29] >> 23) | (T[j + 30] << 6));
				pt[i + 28] = (uint) ((T[j + 30] >> 26) | (T[j + 31] << 3));
				j += Const.INT_SIZE;
			}

			Buffer.BlockCopy(seedA, seedAOffset, publicKeyInput, (Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P) / Const.BYTE_SIZE, Polynomial.SEED);

		}

		/// <summary>
		///     ***********************************************************************************************************************************************************************************
		///     Description:	Encode Public Key for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="publicKeyInput">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">
		///     Starting Point of the Seed A
		/// </param>
		/// <returns>
		///     none
		///     ************************************************************************************************************************************************************************************
		/// </returns>
		public static void encodePublicKeyIIIP(sbyte[] publicKeyInput, long[] T, sbyte[] seedA, int seedAOffset) {

			int j = 0;

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Const.INT_SIZE); i += 15) {
				pt[i + 0] = (uint) (T[j + 0] | (T[j + 1] << 30));
				pt[i + 1] = (uint) ((T[j + 1] >> 2) | (T[j + 2] << 28));
				pt[i + 2] = (uint) ((T[j + 2] >> 4) | (T[j + 3] << 26));
				pt[i + 3] = (uint) ((T[j + 3] >> 6) | (T[j + 4] << 24));
				pt[i + 4] = (uint) ((T[j + 4] >> 8) | (T[j + 5] << 22));
				pt[i + 5] = (uint) ((T[j + 5] >> 10) | (T[j + 6] << 20));
				pt[i + 6] = (uint) ((T[j + 6] >> 12) | (T[j + 7] << 18));
				pt[i + 7] = (uint) ((T[j + 7] >> 14) | (T[j + 8] << 16));
				pt[i + 8] = (uint) ((T[j + 8] >> 16) | (T[j + 9] << 14));
				pt[i + 9] = (uint) ((T[j + 9] >> 18) | (T[j + 10] << 12));
				pt[i + 10] = (uint) ((T[j + 10] >> 20) | (T[j + 11] << 10));
				pt[i + 11] = (uint) ((T[j + 11] >> 22) | (T[j + 12] << 8));
				pt[i + 12] = (uint) ((T[j + 12] >> 24) | (T[j + 13] << 6));
				pt[i + 13] = (uint) ((T[j + 13] >> 26) | (T[j + 14] << 4));
				pt[i + 14] = (uint) ((T[j + 14] >> 28) | (T[j + 15] << 2));
				j += Const.SHORT_SIZE;
			}

			Buffer.BlockCopy(seedA, seedAOffset, publicKeyInput, (Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P) / Const.BYTE_SIZE, Polynomial.SEED);

		}

		/// <summary>
		///     **************************************************************************************************************************************
		///     Description:	Decode Public Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="publicKeyInput">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInputInput">        Public Key to be Decoded </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="qLogarithm">
		///     q <= 2 ^ qLogartihm
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************************************************************************
		/// </returns>
		public static void decodePublicKey(int[] publicKey, sbyte[] seedA, int seedAOffset, sbyte[] publicKeyInput, int n, int qLogarithm) {

			int j = 0;

			uint maskq = (1 << Parameter.Q_LOGARITHM_I) - 1;

			var span1 = publicKey.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_I; i += Const.INT_SIZE) {

				t[i   ] = pt[j] & maskq;
				t[i+ 1] = ((pt[j+ 0] >> 23) | (pt[j+ 1] <<  9)) & maskq;
				t[i+ 2] = ((pt[j+ 1] >> 14) | (pt[j+ 2] << 18)) & maskq; t[i+ 3] = (pt[j+ 2] >> 5) & maskq;
				t[i+ 4] = ((pt[j+ 2] >> 28) | (pt[j+ 3] <<  4)) & maskq;
				t[i+ 5] = ((pt[j+ 3] >> 19) | (pt[j+ 4] << 13)) & maskq;
				t[i+ 6] = ((pt[j+ 4] >> 10) | (pt[j+ 5] << 22)) & maskq; t[i+ 7] = (pt[j+ 5] >> 1) & maskq;
				t[i+ 8] = ((pt[j+ 5] >> 24) | (pt[j+ 6] <<  8)) & maskq;
				t[i+ 9] = ((pt[j+ 6] >> 15) | (pt[j+ 7] << 17)) & maskq; t[i+10] = (pt[j+ 7] >> 6) & maskq;
				t[i+11] = ((pt[j+ 7] >> 29) | (pt[j+ 8] <<  3)) & maskq;
				t[i+12] = ((pt[j+ 8] >> 20) | (pt[j+ 9] << 12)) & maskq;
				t[i+13] = ((pt[j+ 9] >> 11) | (pt[j+10] << 21)) & maskq; t[i+14] = (pt[j+10] >> 2) & maskq;
				t[i+15] = ((pt[j+10] >> 25) | (pt[j+11] <<  7)) & maskq;
				t[i+16] = ((pt[j+11] >> 16) | (pt[j+12] << 16)) & maskq; t[i+17] = (pt[j+12] >> 7) & maskq;
				t[i+18] = ((pt[j+12] >> 30) | (pt[j+13] <<  2)) & maskq;
				t[i+19] = ((pt[j+13] >> 21) | (pt[j+14] << 11)) & maskq;
				t[i+20] = ((pt[j+14] >> 12) | (pt[j+15] << 20)) & maskq; t[i+21] = (pt[j+15] >> 3) & maskq;
				t[i+22] = ((pt[j+15] >> 26) | (pt[j+16] <<  6)) & maskq;
				t[i+23] = ((pt[j+16] >> 17) | (pt[j+17] << 15)) & maskq; t[i+24] = (pt[j+17] >> 8) & maskq;
				t[i+25] = ((pt[j+17] >> 31) | (pt[j+18] <<  1)) & maskq;
				t[i+26] = ((pt[j+18] >> 22) | (pt[j+19] << 10)) & maskq;
				t[i+27] = ((pt[j+19] >> 13) | (pt[j+20] << 19)) & maskq; t[i+28] = (pt[j+20] >> 4) & maskq;
				t[i+29] = ((pt[j+20] >> 27) | (pt[j+21] <<  5)) & maskq;
				t[i+30] = ((pt[j+21] >> 18) | (pt[j+22] << 14)) & maskq;
				t[i+31] = pt[j+22] >> 9;

				j += Parameter.Q_LOGARITHM_I;

			}

			Buffer.BlockCopy(publicKeyInput, (n * qLogarithm) / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///     ***********************************************************************************************************************************************
		///     Description:	Decode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="publicKeyInput">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInputInput">
		///     Public Key to be Decoded
		/// </param>
		/// <returns>
		///     none
		///     ************************************************************************************************************************************************
		/// </returns>
		public static void decodePublicKeyIII(int[] publicKey, sbyte[] seedA, int seedAOffset, sbyte[] publicKeyInput) {

			int j = 0;

			uint maskq = (1 << Parameter.Q_LOGARITHM_III) - 1;

			var span1 = publicKey.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_III; i += Const.INT_SIZE) {

				t[i + 0] = (pt[j + 0]) & maskq;
				t[i + 1] = ((pt[j + 0] >> 24) | (pt[j + 1] << 8)) & maskq;
				t[i + 2] = ((pt[j + 1] >> 16) | (pt[j + 2] << 16)) & maskq;
				t[i + 3] = ((pt[j + 2] >> 8)) & maskq;
				t[i + 4] = (pt[j + 3]) & maskq;
				t[i + 5] = ((pt[j + 3] >> 24) | (pt[j + 4] << 8)) & maskq;
				t[i + 6] = ((pt[j + 4] >> 16) | (pt[j + 5] << 16)) & maskq;
				t[i + 7] = ((pt[j + 5] >> 8)) & maskq;
				t[i + 8] = (pt[j + 6]) & maskq;
				t[i + 9] = ((pt[j + 6] >> 24) | (pt[j + 7] << 8)) & maskq;
				t[i + 10] = ((pt[j + 7] >> 16) | (pt[j + 8] << 16)) & maskq;
				t[i + 11] = ((pt[j + 8] >> 8)) & maskq;
				t[i + 12] = (pt[j + 9]) & maskq;
				t[i + 13] = ((pt[j + 9] >> 24) | (pt[j + 10] << 8)) & maskq;
				t[i + 14] = ((pt[j + 10] >> 16) | (pt[j + 11] << 16)) & maskq;
				t[i + 15] = ((pt[j + 11] >> 8)) & maskq;
				t[i + 16] = (pt[j + 12]) & maskq;
				t[i + 17] = ((pt[j + 12] >> 24) | (pt[j + 13] << 8)) & maskq;
				t[i + 18] = ((pt[j + 13] >> 16) | (pt[j + 14] << 16)) & maskq;
				t[i + 19] = ((pt[j + 14] >> 8)) & maskq;
				t[i + 20] = (pt[j + 15]) & maskq;
				t[i + 21] = ((pt[j + 15] >> 24) | (pt[j + 16] << 8)) & maskq;
				t[i + 22] = ((pt[j + 16] >> 16) | (pt[j + 17] << 16)) & maskq;
				t[i + 23] = ((pt[j + 17] >> 8)) & maskq;
				t[i + 24] = (pt[j + 18]) & maskq;
				t[i + 25] = ((pt[j + 18] >> 24) | (pt[j + 19] << 8)) & maskq;
				t[i + 26] = ((pt[j + 19] >> 16) | (pt[j + 20] << 16)) & maskq;
				t[i + 27] = ((pt[j + 20] >> 8)) & maskq;
				t[i + 28] = (pt[j + 21]) & maskq;
				t[i + 29] = ((pt[j + 21] >> 24) | (pt[j + 22] << 8)) & maskq;
				t[i + 30] = ((pt[j + 22] >> 16) | (pt[j + 23] << 16)) & maskq;
				t[i + 31] = ((pt[j + 23] >> 8)) & maskq;

				j += Parameter.Q_LOGARITHM_III;

			}

			Buffer.BlockCopy(publicKeyInput, (Parameter.N_III * Parameter.Q_LOGARITHM_III) / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///     ***********************************************************************************************************************************************
		///     Description:	Decode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="publicKeyInput">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInputInput">
		///     Public Key to be Decoded
		/// </param>
		/// <returns>
		///     none
		///     ************************************************************************************************************************************************
		/// </returns>
		public static void decodePublicKeyV(int[] publicKey, sbyte[] seedA, int seedAOffset, sbyte[] publicKeyInput) {

			int j = 0;

			uint mask = (1 << Parameter.Q_LOGARITHM_V) - 1;

			var span1 = publicKey.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_V; i += Const.INT_SIZE) {

				t[i + 0] = (pt[j + 0]) & mask;
				t[i + 1] = ((pt[j + 0] >> 25) | (pt[j + 1] << 7)) & mask;
				t[i + 2] = ((pt[j + 1] >> 18) | (pt[j + 2] << 14)) & mask;
				t[i + 3] = ((pt[j + 2] >> 11) | (pt[j + 3] << 21)) & mask;
				t[i + 4] = ((pt[j + 3] >> 4)) & mask;
				t[i + 5] = ((pt[j + 3] >> 29) | (pt[j + 4] << 3)) & mask;
				t[i + 6] = ((pt[j + 4] >> 22) | (pt[j + 5] << 10)) & mask;
				t[i + 7] = ((pt[j + 5] >> 15) | (pt[j + 6] << 17)) & mask;
				t[i + 8] = ((pt[j + 6] >> 8) | (pt[j + 7] << 24)) & mask;
				t[i + 9] = ((pt[j + 7] >> 1)) & mask;
				t[i + 10] = ((pt[j + 7] >> 26) | (pt[j + 8] << 6)) & mask;
				t[i + 11] = ((pt[j + 8] >> 19) | (pt[j + 9] << 13)) & mask;
				t[i + 12] = ((pt[j + 9] >> 12) | (pt[j + 10] << 20)) & mask;
				t[i + 13] = ((pt[j + 10] >> 5)) & mask;
				t[i + 14] = ((pt[j + 10] >> 30) | (pt[j + 11] << 2)) & mask;
				t[i + 15] = ((pt[j + 11] >> 23) | (pt[j + 12] << 9)) & mask;
				t[i + 16] = ((pt[j + 12] >> 16) | (pt[j + 13] << 16)) & mask;
				t[i + 17] = ((pt[j + 13] >> 9) | (pt[j + 14] << 23)) & mask;
				t[i + 18] = ((pt[j + 14] >> 2)) & mask;
				t[i + 19] = ((pt[j + 14] >> 27) | (pt[j + 15] << 5)) & mask;
				t[i + 20] = ((pt[j + 15] >> 20) | (pt[j + 16] << 12)) & mask;
				t[i + 21] = ((pt[j + 16] >> 13) | (pt[j + 17] << 19)) & mask;
				t[i + 22] = ((pt[j + 17] >> 6)) & mask;
				t[i + 23] = ((pt[j + 17] >> 31) | (pt[j + 18] << 1)) & mask;
				t[i + 24] = ((pt[j + 18] >> 24) | (pt[j + 19] << 8)) & mask;
				t[i + 25] = ((pt[j + 19] >> 17) | (pt[j + 20] << 15)) & mask;
				t[i + 26] = ((pt[j + 20] >> 10) | (pt[j + 21] << 22)) & mask;
				t[i + 27] = ((pt[j + 21] >> 3)) & mask;
				t[i + 28] = ((pt[j + 21] >> 28) | (pt[j + 22] << 4)) & mask;
				t[i + 29] = ((pt[j + 22] >> 21) | (pt[j + 23] << 11)) & mask;
				t[i + 30] = ((pt[j + 23] >> 14) | (pt[j + 24] << 18)) & mask;
				t[i + 31] = ((pt[j + 24] >> 7)) & mask;

				j += Parameter.Q_LOGARITHM_V;

			}

			Buffer.BlockCopy(publicKeyInput, (Parameter.N_V * Parameter.Q_LOGARITHM_V) / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///     **********************************************************************************************************************************************************
		///     Description:	Decode Public Key for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="publicKeyInput">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInputInput">
		///     Public Key to be Decoded
		/// </param>
		/// <returns>
		///     none
		///     ***********************************************************************************************************************************************************
		/// </returns>
		public static void decodePublicKeyIP(int[] publicKey, sbyte[] seedA, int seedAOffset, sbyte[] publicKeyInput) {

			int j = 0;

			uint mask29 = (1 << Parameter.Q_LOGARITHM_I_P) - 1;
			
			var span1 = publicKey.AsSpan();
			Span<uint> pp = MemoryMarshal.Cast<int, uint>(span1);

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_I_P * Parameter.K_I_P; i += (Const.INT_SIZE)) {
				pp[i] = pt[j] & mask29;
				pp[i + 1] = ((pt[j + 0] >> 29) | (pt[j + 1] << 3)) & mask29;
				pp[i + 2] = ((pt[j + 1] >> 26) | (pt[j + 2] << 6)) & mask29;
				pp[i + 3] = ((pt[j + 2] >> 23) | (pt[j + 3] << 9)) & mask29;
				pp[i + 4] = ((pt[j + 3] >> 20) | (pt[j + 4] << 12)) & mask29;
				pp[i + 5] = ((pt[j + 4] >> 17) | (pt[j + 5] << 15)) & mask29;
				pp[i + 6] = ((pt[j + 5] >> 14) | (pt[j + 6] << 18)) & mask29;
				pp[i + 7] = ((pt[j + 6] >> 11) | (pt[j + 7] << 21)) & mask29;
				pp[i + 8] = ((pt[j + 7] >> 8) | (pt[j + 8] << 24)) & mask29;
				pp[i + 9] = ((pt[j + 8] >> 5) | (pt[j + 9] << 27)) & mask29;
				pp[i + 10] = (pt[j + 9] >> 2) & mask29;
				pp[i + 11] = ((pt[j + 9] >> 31) | (pt[j + 10] << 1)) & mask29;
				pp[i + 12] = ((pt[j + 10] >> 28) | (pt[j + 11] << 4)) & mask29;
				pp[i + 13] = ((pt[j + 11] >> 25) | (pt[j + 12] << 7)) & mask29;
				pp[i + 14] = ((pt[j + 12] >> 22) | (pt[j + 13] << 10)) & mask29;
				pp[i + 15] = ((pt[j + 13] >> 19) | (pt[j + 14] << 13)) & mask29;
				pp[i + 16] = ((pt[j + 14] >> 16) | (pt[j + 15] << 16)) & mask29;
				pp[i + 17] = ((pt[j + 15] >> 13) | (pt[j + 16] << 19)) & mask29;
				pp[i + 18] = ((pt[j + 16] >> 10) | (pt[j + 17] << 22)) & mask29;
				pp[i + 19] = ((pt[j + 17] >> 7) | (pt[j + 18] << 25)) & mask29;
				pp[i + 20] = ((pt[j + 18] >> 4) | (pt[j + 19] << 28)) & mask29;
				pp[i + 21] = (pt[j + 19] >> 1) & mask29;
				pp[i + 22] = ((pt[j + 19] >> 30) | (pt[j + 20] << 2)) & mask29;
				pp[i + 23] = ((pt[j + 20] >> 27) | (pt[j + 21] << 5)) & mask29;
				pp[i + 24] = ((pt[j + 21] >> 24) | (pt[j + 22] << 8)) & mask29;
				pp[i + 25] = ((pt[j + 22] >> 21) | (pt[j + 23] << 11)) & mask29;
				pp[i + 26] = ((pt[j + 23] >> 18) | (pt[j + 24] << 14)) & mask29;
				pp[i + 27] = ((pt[j + 24] >> 15) | (pt[j + 25] << 17)) & mask29;
				pp[i + 28] = ((pt[j + 25] >> 12) | (pt[j + 26] << 20)) & mask29;
				pp[i + 29] = ((pt[j + 26] >> 9) | (pt[j + 27] << 23)) & mask29;
				pp[i + 30] = ((pt[j + 27] >> 6) | (pt[j + 28] << 26)) & mask29;
				pp[i + 31] = pt[j + 28] >> 3;
				j += 29;
			}

			Buffer.BlockCopy(publicKeyInput, (Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P) / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///     **************************************************************************************************************************************************************
		///     Description:	Decode Public Key for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="publicKeyInput">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInputInput">
		///     Public Key to be Decoded
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************************************************************************************************
		/// </returns>
		public static void decodePublicKeyIIIP(int[] publicKey, sbyte[] seedA, int seedAOffset, sbyte[] publicKeyInput) {

			int j = 0;

			uint maskq = (1 << Parameter.Q_LOGARITHM_III_P) - 1;

			var span1 = publicKey.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = publicKeyInput.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_III_P * Parameter.K_III_P; i += (Const.SHORT_SIZE)) {
				t[i + 0] = (pt[j + 0]) & maskq;
				t[i + 1] = ((pt[j + 0] >> 30) | (pt[j + 1] << 2)) & maskq;
				t[i + 2] = ((pt[j + 1] >> 28) | (pt[j + 2] << 4)) & maskq;
				t[i + 3] = ((pt[j + 2] >> 26) | (pt[j + 3] << 6)) & maskq;
				t[i + 4] = ((pt[j + 3] >> 24) | (pt[j + 4] << 8)) & maskq;
				t[i + 5] = ((pt[j + 4] >> 22) | (pt[j + 5] << 10)) & maskq;
				t[i + 6] = ((pt[j + 5] >> 20) | (pt[j + 6] << 12)) & maskq;
				t[i + 7] = ((pt[j + 6] >> 18) | (pt[j + 7] << 14)) & maskq;
				t[i + 8] = ((pt[j + 7] >> 16) | (pt[j + 8] << 16)) & maskq;
				t[i + 9] = ((pt[j + 8] >> 14) | (pt[j + 9] << 18)) & maskq;
				t[i + 10] = ((pt[j + 9] >> 12) | (pt[j + 10] << 20)) & maskq;
				t[i + 11] = ((pt[j + 10] >> 10) | (pt[j + 11] << 22)) & maskq;
				t[i + 12] = ((pt[j + 11] >> 8) | (pt[j + 12] << 24)) & maskq;
				t[i + 13] = ((pt[j + 12] >> 6) | (pt[j + 13] << 26)) & maskq;
				t[i + 14] = ((pt[j + 13] >> 4) | (pt[j + 14] << 28)) & maskq;
				t[i + 15] = ((pt[j + 14] >> 2)) & maskq;
				j += 15;
			}

			Buffer.BlockCopy(publicKeyInput, (Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P) / Const.BYTE_SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///     *************************************************************************************************************************************************************************************************************
		///     Description:	Encode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z"> </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="d">
		///     Number of Rounded Bits
		/// </param>
		/// <returns>
		///     none
		///     **************************************************************************************************************************************************************************************************************
		/// </returns>
		public static void encodeSignature(sbyte[] signature, int signatureOffset, sbyte[] C, int cOffset, int[] Z, int n, int d) {

			int j = 0;

			uint maskd = ((1 << (Parameter.B_BIT_I + 1)) - 1);

			var span1 = Z.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for (int i=0; i<(Parameter.N_I*(Parameter.B_BIT_I+1)/Const.INT_SIZE); i+=(Parameter.B_BIT_I+1)) {
				pt[i   ] = (t[j] & ((1<<21)-1)) | (t[j+1] << 21);
				pt[i+ 1] = ((t[j+ 1] >> 11) & ((1<<10)-1)) | ((t[j+ 2] & maskd) << 10) | (t[j+ 3] << 31);
				pt[i+ 2] = ((t[j+ 3] >>  1) & ((1<<20)-1)) | (t[j+4] << 20);
				pt[i+ 3] = ((t[j+ 4] >> 12) & ((1<<9)-1 )) | ((t[j+ 5] & maskd) <<  9) | (t[j+ 6] << 30);
				pt[i+ 4] = ((t[j+ 6] >>  2) & ((1<<19)-1)) | (t[j+7] << 19);
				pt[i+ 5] = ((t[j+ 7] >> 13) & ((1<<8)-1 )) | ((t[j+ 8] & maskd) <<  8) | (t[j+ 9] << 29);
				pt[i+ 6] = ((t[j+ 9] >>  3) & ((1<<18)-1)) | (t[j+10] << 18);
				pt[i+ 7] = ((t[j+10] >> 14) & ((1<<7)-1 )) | ((t[j+11] & maskd) <<  7) | (t[j+12] << 28);
				pt[i+ 8] = ((t[j+12] >>  4) & ((1<<17)-1)) | (t[j+13] << 17);
				pt[i+ 9] = ((t[j+13] >> 15) & ((1<<6)-1 )) | ((t[j+14] & maskd) <<  6) | (t[j+15] << 27);
				pt[i+10] = ((t[j+15] >>  5) & ((1<<16)-1)) | (t[j+16] << 16);
				pt[i+11] = ((t[j+16] >> 16) & ((1<<5)-1 )) | ((t[j+17] & maskd) <<  5) | (t[j+18] << 26);
				pt[i+12] = ((t[j+18] >>  6) & ((1<<15)-1)) | (t[j+19] << 15);
				pt[i+13] = ((t[j+19] >> 17) & ((1<<4)-1 )) | ((t[j+20] & maskd) <<  4) | (t[j+21] << 25);
				pt[i+14] = ((t[j+21] >>  7) & ((1<<14)-1)) | (t[j+22] << 14);
				pt[i+15] = ((t[j+22] >> 18) & ((1<<3)-1 )) | ((t[j+23] & maskd) <<  3) | (t[j+24] << 24);
				pt[i+16] = ((t[j+24] >>  8) & ((1<<13)-1)) | (t[j+25] << 13);
				pt[i+17] = ((t[j+25] >> 19) & ((1<<2)-1 )) | ((t[j+26] & maskd) <<  2) | (t[j+27] << 23);
				pt[i+18] = ((t[j+27] >>  9) & ((1<<12)-1)) | (t[j+28] << 12);
				pt[i+19] = ((t[j+28] >> 20) & ((1<<1)-1 )) | ((t[j+29] & maskd) <<  1) | (t[j+30] << 22);
				pt[i+20] = ((t[j+30] >> 10) & ((1<<11)-1)) | (t[j+31] << 11);
				j += Const.INT_SIZE;
			}

			Buffer.BlockCopy(C, cOffset, signature, signatureOffset + ((Parameter.N_I * (Parameter.B_BIT_I + 1)) / Const.BYTE_SIZE), Polynomial.HASH);

		}

		/// <summary>
		///     ***********************************************************************************************************************************************************************************************************
		///     Description:	Encode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns>
		///     none
		///     ************************************************************************************************************************************************************************************************************
		/// </returns>
		public static void encodeSignatureIII(sbyte[] signature, int signatureOffset, sbyte[] C, int cOffset, int[] Z) {

			int j = 0;

			uint mask = ((1 << (Parameter.B_BIT_III + 1)) - 1);

			var span1 = Z.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_III * (Parameter.B_BIT_III + 1) / Const.INT_SIZE); i += ((Parameter.B_BIT_III + 1) / 2)) {
				pt[i] = (t[j] & ((1 << 22) - 1)) | (t[j + 1] << 22);
				pt[i + 1] = ((t[j + 1] >> 10) & ((1 << 12) - 1)) | (t[j + 2] << 12);
				pt[i + 2] = ((t[j + 2] >> 20) & ((1 << 2) - 1)) | ((t[j + 3] & ((1 << 22) - 1)) << 2) | (t[j + 4] << 24);
				pt[i + 3] = ((t[j + 4] >> 8) & ((1 << 14) - 1)) | (t[j + 5] << 14);
				pt[i + 4] = ((t[j + 5] >> 18) & ((1 << 4) - 1)) | ((t[j + 6] & ((1 << 22) - 1)) << 4) | (t[j + 7] << 26);
				pt[i + 5] = ((t[j + 7] >> 6) & ((1 << 16) - 1)) | (t[j + 8] << 16);
				pt[i + 6] = ((t[j + 8] >> 16) & ((1 << 6) - 1)) | ((t[j + 9] & ((1 << 22) - 1)) << 6) | (t[j + 10] << 28);
				pt[i + 7] = ((t[j + 10] >> 4) & ((1 << 18) - 1)) | (t[j + 11] << 18);
				pt[i + 8] = ((t[j + 11] >> 14) & ((1 << 8) - 1)) | ((t[j + 12] & ((1 << 22) - 1)) << 8) | (t[j + 13] << 30);
				pt[i + 9] = ((t[j + 13] >> 2) & ((1 << 20) - 1)) | (t[j + 14] << 20);
				pt[i + 10] = ((t[j + 14] >> 12) & ((1 << 10) - 1)) | (t[j + 15] << 10);
				j += Const.SHORT_SIZE;
			}

			Buffer.BlockCopy(C, cOffset, signature, signatureOffset + ((Parameter.N_III * (Parameter.B_BIT_III + 1)) / Const.BYTE_SIZE), Polynomial.HASH);

		}

		/// <summary>
		///     ***********************************************************************************************************************************************************************************************************
		///     Description:	Encode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns>
		///     none
		///     ************************************************************************************************************************************************************************************************************
		/// </returns>
		public static void encodeSignatureV(sbyte[] signature, int signatureOffset, sbyte[] C, int cOffset, int[] Z) {

			int j = 0;
			uint mask = ((1 << (Parameter.B_BIT_V + 1)) - 1);

			var span1 = Z.AsSpan();
			Span<uint> t = MemoryMarshal.Cast<int, uint>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_V * (Parameter.B_BIT_V + 1) / Const.INT_SIZE); i += (Parameter.B_BIT_V + 1)) {
				pt[i + 0] = ((t[j + 0] & ((1 << 23) - 1)) | (t[j + 1] << 23));
				pt[i + 1] = (((t[j + 1] >> 9) & ((1 << 14) - 1)) | (t[j + 2] << 14));
				pt[i + 2] = ((t[j + 2] >> 18) & ((1 << 5) - 1)) | ((t[j + 3] & mask) << 5) | (t[j + 4] << 28);
				pt[i + 3] = (((t[j + 4] >> 4) & ((1 << 19) - 1)) | (t[j + 5] << 19));
				pt[i + 4] = (((t[j + 5] >> 13) & ((1 << 10) - 1)) | (t[j + 6] << 10));
				pt[i + 5] = ((t[j + 6] >> 22) & ((1 << 1) - 1)) | ((t[j + 7] & mask) << 1) | (t[j + 8] << 24);
				pt[i + 6] = (((t[j + 8] >> 8) & ((1 << 15) - 1)) | (t[j + 9] << 15));
				pt[i + 7] = ((t[j + 9] >> 17) & ((1 << 6) - 1)) | ((t[j + 10] & mask) << 6) | (t[j + 11] << 29);
				pt[i + 8] = (((t[j + 11] >> 3) & ((1 << 20) - 1)) | (t[j + 12] << 20));
				pt[i + 9] = (((t[j + 12] >> 12) & ((1 << 11) - 1)) | (t[j + 13] << 11));
				pt[i + 10] = ((t[j + 13] >> 21) & ((1 << 2) - 1)) | ((t[j + 14] & mask) << 2) | (t[j + 15] << 25);
				pt[i + 11] = (((t[j + 15] >> 7) & ((1 << 16) - 1)) | (t[j + 16] << 16));
				pt[i + 12] = ((t[j + 16] >> 16) & ((1 << 7) - 1)) | ((t[j + 17] & mask) << 7) | (t[j + 18] << 30);
				pt[i + 13] = (((t[j + 18] >> 2) & ((1 << 21) - 1)) | (t[j + 19] << 21));
				pt[i + 14] = (((t[j + 19] >> 11) & ((1 << 12) - 1)) | (t[j + 20] << 12));
				pt[i + 15] = ((t[j + 20] >> 20) & ((1 << 3) - 1)) | ((t[j + 21] & mask) << 3) | (t[j + 22] << 26);
				pt[i + 16] = (((t[j + 22] >> 6) & ((1 << 17) - 1)) | (t[j + 23] << 17));
				pt[i + 17] = ((t[j + 23] >> 15) & ((1 << 8) - 1)) | ((t[j + 24] & mask) << 8) | (t[j + 25] << 31);
				pt[i + 18] = (((t[j + 25] >> 1) & ((1 << 22) - 1)) | (t[j + 26] << 22));
				pt[i + 19] = (((t[j + 26] >> 10) & ((1 << 13) - 1)) | (t[j + 27] << 13));
				pt[i + 20] = ((t[j + 27] >> 19) & ((1 << 4) - 1)) | ((t[j + 28] & mask) << 4) | (t[j + 29] << 27);
				pt[i + 21] = (((t[j + 29] >> 5) & ((1 << 18) - 1)) | (t[j + 30] << 18));
				pt[i + 22] = (((t[j + 30] >> 14) & ((1 << 9) - 1)) | (t[j + 31] << 9));
				j += Const.INT_SIZE;
			}

			Buffer.BlockCopy(C, cOffset, signature, signatureOffset + ((Parameter.N_V * (Parameter.B_BIT_V + 1)) / Const.BYTE_SIZE), Polynomial.HASH);

		}

		/// <summary>
		///     ***********************************************************************************************************************************************************************************************************
		///     Description:	Encode Signature for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns>
		///     none
		///     ************************************************************************************************************************************************************************************************************
		/// </returns>
		public static void encodeSignatureIP(sbyte[] signature, int signatureOffset, sbyte[] C, int cOffset, long[] Z) {

			int j = 0;

			ulong mask = ((1 << (Parameter.B_BIT_I_P + 1)) - 1);

			var span1 = Z.AsSpan();
			Span<ulong> t = MemoryMarshal.Cast<long, ulong>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_I_P * (Parameter.B_BIT_I_P + 1) / Const.INT_SIZE); i += 10) {
				pt[i] = (uint) ((t[j] & ((1 << 20) - 1)) | (t[j + 1] << 20));
				pt[i + 1] = (uint) (((t[j + 1] >> 12) & ((1 << 8) - 1)) | ((t[j + 2] & mask) << 8) | (t[j + 3] << 28));
				pt[i + 2] = (uint) (((t[j + 3] >> 4) & ((1 << 16) - 1)) | (t[j + 4] << 16));
				pt[i + 3] = (uint) (((t[j + 4] >> 16) & ((1 << 4) - 1)) | ((t[j + 5] & mask) << 4) | (t[j + 6] << 24));
				pt[i + 4] = (uint) (((t[j + 6] >> 8) & ((1 << 12) - 1)) | (t[j + 7] << 12));
				pt[i + 5] = (uint) ((t[j + 8] & ((1 << 20) - 1)) | (t[j + 9] << 20));
				pt[i + 6] = (uint) (((t[j + 9] >> 12) & ((1 << 8) - 1)) | ((t[j + 10] & mask) << 8) | (t[j + 11] << 28));
				pt[i + 7] = (uint) (((t[j + 11] >> 4) & ((1 << 16) - 1)) | (t[j + 12] << 16));
				pt[i + 8] = (uint) (((t[j + 12] >> 16) & ((1 << 4) - 1)) | ((t[j + 13] & mask) << 4) | (t[j + 14] << 24));
				pt[i + 9] = (uint) (((t[j + 14] >> 8) & ((1 << 12) - 1)) | (t[j + 15] << 12));
				j += Const.SHORT_SIZE;
			}

			Buffer.BlockCopy(C, cOffset, signature, signatureOffset + ((Parameter.N_I_P * (Parameter.B_BIT_I_P + 1)) / Const.BYTE_SIZE), Polynomial.HASH);

		}

		/// <summary>
		///     *************************************************************************************************************************************************************
		///     Description:	Encode Signature for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns>
		///     none
		///     **************************************************************************************************************************************************************
		/// </returns>
		public static void encodeSignatureIIIP(sbyte[] signature, int signatureOffset, sbyte[] C, int cOffset, long[] Z) {

			int j = 0;

			ulong mask = ((1 << (Parameter.B_BIT_III_P + 1)) - 1);

			var span1 = Z.AsSpan();
			Span<ulong> t = MemoryMarshal.Cast<long, ulong>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < (Parameter.N_III_P * (Parameter.B_BIT_III_P + 1) / Const.INT_SIZE); i += 11) {
				pt[i + 0] = (uint) ((t[j + 0] & ((1 << 22) - 1)) | (t[j + 1] << 22));
				pt[i + 1] = (uint) (((t[j + 1] >> 10) & ((1 << 12) - 1)) | (t[j + 2] << 12));
				pt[i + 2] = (uint) (((t[j + 2] >> 20) & ((1 << 2) - 1)) | ((t[j + 3] & mask) << 2) | (t[j + 4] << 24));
				pt[i + 3] = (uint) (((t[j + 4] >> 8) & ((1 << 14) - 1)) | (t[j + 5] << 14));
				pt[i + 4] = (uint) (((t[j + 5] >> 18) & ((1 << 4) - 1)) | ((t[j + 6] & mask) << 4) | (t[j + 7] << 26));
				pt[i + 5] = (uint) (((t[j + 7] >> 6) & ((1 << 16) - 1)) | (t[j + 8] << 16));
				pt[i + 6] = (uint) (((t[j + 8] >> 16) & ((1 << 6) - 1)) | ((t[j + 9] & mask) << 6) | (t[j + 10] << 28));
				pt[i + 7] = (uint) (((t[j + 10] >> 4) & ((1 << 18) - 1)) | (t[j + 11] << 18));
				pt[i + 8] = (uint) (((t[j + 11] >> 14) & ((1 << 8) - 1)) | ((t[j + 12] & mask) << 8) | (t[j + 13] << 30));
				pt[i + 9] = (uint) (((t[j + 13] >> 2) & ((1 << 20) - 1)) | (t[j + 14] << 20));
				pt[i + 10] = (uint) (((t[j + 14] >> 12) & ((1 << 10) - 1)) | (t[j + 15] << 10));
				j += Const.SHORT_SIZE;
			}

			Buffer.BlockCopy(C, cOffset, signature, signatureOffset + ((Parameter.N_III_P * (Parameter.B_BIT_III_P + 1)) / Const.BYTE_SIZE), Polynomial.HASH);

		}

		/// <summary>
		///     ****************************************************************************************************************************
		///     Description:	Decode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="d">
		///     Number of Rounded Bits
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************
		/// </returns>
		public static void decodeSignature(sbyte[] C, int[] Z, sbyte[] signature, int signatureOffset, int n, int d) {

			int j = 0;

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_I; i += Const.INT_SIZE) {
				Z[i   ] = (int)(pt[j+ 0] << 11) >> 11; Z[i+ 1] = (int)(pt[j+ 0] >> 21) | ((int)(pt[j+ 1] << 22) >> 11);
			    Z[i+ 2] = (int)(pt[j+ 1] <<  1) >> 11; Z[i+ 3] = (int)(pt[j+ 1] >> 31) | ((int)(pt[j+ 2] << 12) >> 11);
			    Z[i+ 4] = (int)(pt[j+ 2] >> 20) | ((int)(pt[j+ 3] << 23) >> 11);
			    Z[i+ 5] = (int)(pt[j+ 3] <<  2) >> 11; Z[i+ 6] = (int)(pt[j+ 3] >> 30) | ((int)(pt[j+ 4] << 13) >> 11);
			    Z[i+ 7] = (int)(pt[j+ 4] >> 19) | ((int)(pt[j+ 5] << 24) >> 11);
			    Z[i+ 8] = (int)(pt[j+ 5] <<  3) >> 11; Z[i+ 9] = (int)(pt[j+ 5] >> 29) | ((int)(pt[j+ 6] << 14) >> 11);
			    Z[i+10] = (int)(pt[j+ 6] >> 18) | ((int)(pt[j+ 7] << 25) >> 11);
			    Z[i+11] = (int)(pt[j+ 7] <<  4) >> 11; Z[i+12] = (int)(pt[j+ 7] >> 28) | ((int)(pt[j+ 8] << 15) >> 11);
			    Z[i+13] = (int)(pt[j+ 8] >> 17) | ((int)(pt[j+ 9] << 26) >> 11);
			    Z[i+14] = (int)(pt[j+ 9] <<  5) >> 11; Z[i+15] = (int)(pt[j+ 9] >> 27) | ((int)(pt[j+10] << 16) >> 11);
			    Z[i+16] = (int)(pt[j+10] >> 16) | ((int)(pt[j+11] << 27) >> 11);
			    Z[i+17] = (int)(pt[j+11] <<  6) >> 11; Z[i+18] = (int)(pt[j+11] >> 26) | ((int)(pt[j+12] << 17) >> 11);
			    Z[i+19] = (int)(pt[j+12] >> 15) | ((int)(pt[j+13] << 28) >> 11);
			    Z[i+20] = (int)(pt[j+13] <<  7) >> 11; Z[i+21] = (int)(pt[j+13] >> 25) | ((int)(pt[j+14] << 18) >> 11);
			    Z[i+22] = (int)(pt[j+14] >> 14) | ((int)(pt[j+15] << 29) >> 11);
			    Z[i+23] = (int)(pt[j+15] <<  8) >> 11; Z[i+24] = (int)(pt[j+15] >> 24) | ((int)(pt[j+16] << 19) >> 11);
			    Z[i+25] = (int)(pt[j+16] >> 13) | ((int)(pt[j+17] << 30) >> 11);
			    Z[i+26] = (int)(pt[j+17] <<  9) >> 11; Z[i+27] = (int)(pt[j+17] >> 23) | ((int)(pt[j+18] << 20) >> 11);
			    Z[i+28] = (int)(pt[j+18] >> 12) | ((int)(pt[j+19] << 31) >> 11);
			    Z[i+29] = (int)(pt[j+19] << 10) >> 11; Z[i+30] = (int)(pt[j+19] >> 22) | ((int)(pt[j+20] << 21) >> 11);
			    Z[i+31] = (int)pt[j+20] >> 11;
				j += (Parameter.B_BIT_I+1);
			}

			Buffer.BlockCopy(signature, signatureOffset + ((Parameter.N_I * (Parameter.B_BIT_I + 1)) / Const.BYTE_SIZE), C, 0, Polynomial.HASH);

		}

		/// <summary>
		///     ************************************************************************************************************************************
		///     Description:	Decode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">
		///     Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************
		/// </returns>
		public static void decodeSignatureIII(sbyte[] C, int[] Z, sbyte[] signature, int signatureOffset) {

			int j = 0;

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_III; i += Const.SHORT_SIZE) {
				Z[i] = ((int) pt[j + 0] << 10) >> 10;
				Z[i + 1] = (int) (pt[j + 0] >> 22) | ((int) (pt[j + 1] << 20) >> 10);
				Z[i + 2] = (int) (pt[j + 1] >> 12) | ((int) (pt[j + 2] << 30) >> 10);
				Z[i + 3] = (int) (pt[j + 2] << 8) >> 10;
				Z[i + 4] = (int) (pt[j + 2] >> 24) | ((int) (pt[j + 3] << 18) >> 10);
				Z[i + 5] = (int) (pt[j + 3] >> 14) | ((int) (pt[j + 4] << 28) >> 10);
				Z[i + 6] = (int) (pt[j + 4] << 6) >> 10;
				Z[i + 7] = (int) (pt[j + 4] >> 26) | ((int) (pt[j + 5] << 16) >> 10);
				Z[i + 8] = (int) (pt[j + 5] >> 16) | ((int) (pt[j + 6] << 26) >> 10);
				Z[i + 9] = (int) (pt[j + 6] << 4) >> 10;
				Z[i + 10] = (int) (pt[j + 6] >> 28) | ((int) (pt[j + 7] << 14) >> 10);
				Z[i + 11] = (int) (pt[j + 7] >> 18) | ((int) (pt[j + 8] << 24) >> 10);
				Z[i + 12] = (int) (pt[j + 8] << 2) >> 10;
				Z[i + 13] = (int) (pt[j + 8] >> 30) | ((int) (pt[j + 9] << 12) >> 10);
				Z[i + 14] = (int) (pt[j + 9] >> 20) | ((int) (pt[j + 10] << 22) >> 10);
				Z[i + 15] = (int) pt[j + 10] >> 10;
				j += 11;
			}

			Buffer.BlockCopy(signature, signatureOffset + ((Parameter.N_III * (Parameter.B_BIT_III + 1)) / Const.BYTE_SIZE), C, 0, Polynomial.HASH);

		}

		/// <summary>
		///     ************************************************************************************************************************************
		///     Description:	Decode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">
		///     Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************
		/// </returns>
		public static void decodeSignatureV(sbyte[] C, int[] Z, sbyte[] signature, int signatureOffset) {

			int j = 0;

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_V; i += Const.INT_SIZE) {
				Z[i + 0] = ((int) pt[j + 0] << 9) >> 9;
				Z[i + 1] = (int) (pt[j + 0] >> 23) | ((int) (pt[j + 1] << 18) >> 9);
				Z[i + 2] = (int) (pt[j + 1] >> 14) | ((int) (pt[j + 2] << 27) >> 9);
				Z[i + 3] = ((int) pt[j + 2] << 4) >> 9;
				Z[i + 4] = (int) (pt[j + 2] >> 28) | ((int) (pt[j + 3] << 13) >> 9);
				Z[i + 5] = (int) (pt[j + 3] >> 19) | ((int) (pt[j + 4] << 22) >> 9);
				Z[i + 6] = (int) (pt[j + 4] >> 10) | ((int) (pt[j + 5] << 31) >> 9);
				Z[i + 7] = ((int) pt[j + 5] << 8) >> 9;
				Z[i + 8] = (int) (pt[j + 5] >> 24) | ((int) (pt[j + 6] << 17) >> 9);
				Z[i + 9] = (int) (pt[j + 6] >> 15) | ((int) (pt[j + 7] << 26) >> 9);
				Z[i + 10] = ((int) pt[j + 7] << 3) >> 9;
				Z[i + 11] = (int) (pt[j + 7] >> 29) | ((int) (pt[j + 8] << 12) >> 9);
				Z[i + 12] = (int) (pt[j + 8] >> 20) | ((int) (pt[j + 9] << 21) >> 9);
				Z[i + 13] = (int) (pt[j + 9] >> 11) | ((int) (pt[j + 10] << 30) >> 9);
				Z[i + 14] = ((int) pt[j + 10] << 7) >> 9;
				Z[i + 15] = (int) (pt[j + 10] >> 25) | ((int) (pt[j + 11] << 16) >> 9);
				Z[i + 16] = (int) (pt[j + 11] >> 16) | ((int) (pt[j + 12] << 25) >> 9);
				Z[i + 17] = ((int) pt[j + 12] << 2) >> 9;
				Z[i + 18] = (int) (pt[j + 12] >> 30) | ((int) (pt[j + 13] << 11) >> 9);
				Z[i + 19] = (int) (pt[j + 13] >> 21) | ((int) (pt[j + 14] << 20) >> 9);
				Z[i + 20] = (int) (pt[j + 14] >> 12) | ((int) (pt[j + 15] << 29) >> 9);
				Z[i + 21] = ((int) pt[j + 15] << 6) >> 9;
				Z[i + 22] = (int) (pt[j + 15] >> 26) | ((int) (pt[j + 16] << 15) >> 9);
				Z[i + 23] = (int) (pt[j + 16] >> 17) | ((int) (pt[j + 17] << 24) >> 9);
				Z[i + 24] = ((int) pt[j + 17] << 1) >> 9;
				Z[i + 25] = (int) (pt[j + 17] >> 31) | ((int) (pt[j + 18] << 10) >> 9);
				Z[i + 26] = (int) (pt[j + 18] >> 22) | ((int) (pt[j + 19] << 19) >> 9);
				Z[i + 27] = (int) (pt[j + 19] >> 13) | ((int) (pt[j + 20] << 28) >> 9);
				Z[i + 28] = ((int) pt[j + 20] << 5) >> 9;
				Z[i + 29] = (int) (pt[j + 20] >> 27) | ((int) (pt[j + 21] << 14) >> 9);
				Z[i + 30] = (int) (pt[j + 21] >> 18) | ((int) (pt[j + 22] << 23) >> 9);
				Z[i + 31] = (int) pt[j + 22] >> 9;
				j += (Parameter.B_BIT_V + 1);
			}

			Buffer.BlockCopy(signature, signatureOffset + ((Parameter.N_V * (Parameter.B_BIT_V + 1)) / Const.BYTE_SIZE), C, 0, Polynomial.HASH);

		}

		/// <summary>
		///     **************************************************************************************************************************
		///     Description:	Decode Signature for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">
		///     Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************************************************************
		/// </returns>
		public static void decodeSignatureIP(sbyte[] C, long[] Z, sbyte[] signature, int signatureOffset) {

			int j = 0;

			var span1 = Z.AsSpan();
			Span<ulong> t = MemoryMarshal.Cast<long, ulong>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_I_P; i += Const.SHORT_SIZE) {
				Z[i] = ((int) pt[j + 0] << 12) >> 12;
				Z[i + 1] = (int) (pt[j + 0] >> 20) | ((int) (pt[j + 1] << 24) >> 12);
				Z[i + 2] = ((int) pt[j + 1] << 4) >> 12;
				Z[i + 3] = (int) (pt[j + 1] >> 28) | ((int) (pt[j + 2] << 16) >> 12);
				Z[i + 4] = (int) (pt[j + 2] >> 16) | ((int) (pt[j + 3] << 28) >> 12);
				Z[i + 5] = ((int) pt[j + 3] << 8) >> 12;
				Z[i + 6] = (int) (pt[j + 3] >> 24) | ((int) (pt[j + 4] << 20) >> 12);
				Z[i + 7] = (int) pt[j + 4] >> 12;
				Z[i + 8] = ((int) pt[j + 5] << 12) >> 12;
				Z[i + 9] = (int) (pt[j + 5] >> 20) | ((int) (pt[j + 6] << 24) >> 12);
				Z[i + 10] = ((int) pt[j + 6] << 4) >> 12;
				Z[i + 11] = (int) (pt[j + 6] >> 28) | ((int) (pt[j + 7] << 16) >> 12);
				Z[i + 12] = (int) (pt[j + 7] >> 16) | ((int) (pt[j + 8] << 28) >> 12);
				Z[i + 13] = ((int) pt[j + 8] << 8) >> 12;
				Z[i + 14] = (int) (pt[j + 8] >> 24) | ((int) (pt[j + 9] << 20) >> 12);
				Z[i + 15] = (int) pt[j + 9] >> 12;
				j += 10;
			}

			Buffer.BlockCopy(signature, signatureOffset + ((Parameter.N_I_P * Parameter.D_I_P) / Const.BYTE_SIZE), C, 0, Polynomial.HASH);

		}

		/// <summary>
		///     **************************************************************************************************************************************
		///     Description:	Decode Signature for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">
		///     Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************************************************************************
		/// </returns>
		public static void decodeSignatureIIIP(sbyte[] C, long[] Z, sbyte[] signature, int signatureOffset) {

			int j = 0;

			ulong mask = ((1 << (Parameter.B_BIT_III_P + 1)) - 1);

			var span1 = Z.AsSpan();
			Span<ulong> t = MemoryMarshal.Cast<long, ulong>(span1);

			var span = signature.AsSpan();
			Span<uint> pt = MemoryMarshal.Cast<sbyte, uint>(span);

			for(int i = 0; i < Parameter.N_III_P; i += Const.SHORT_SIZE) {
				Z[i + 0] = ((int) pt[j + 0] << 10) >> 10;
				Z[i + 1] = (int) (pt[j + 0] >> 22) | ((int) (pt[j + 1] << 20) >> 10);
				Z[i + 2] = (int) (pt[j + 1] >> 12) | ((int) (pt[j + 2] << 30) >> 10);
				Z[i + 3] = ((int) pt[j + 2] << 8) >> 10;
				Z[i + 4] = (int) (pt[j + 2] >> 24) | ((int) (pt[j + 3] << 18) >> 10);
				Z[i + 5] = (int) (pt[j + 3] >> 14) | ((int) (pt[j + 4] << 28) >> 10);
				Z[i + 6] = ((int) pt[j + 4] << 6) >> 10;
				Z[i + 7] = (int) (pt[j + 4] >> 26) | ((int) (pt[j + 5] << 16) >> 10);
				Z[i + 8] = (int) (pt[j + 5] >> 16) | ((int) (pt[j + 6] << 26) >> 10);
				Z[i + 9] = ((int) pt[j + 6] << 4) >> 10;
				Z[i + 10] = (int) (pt[j + 6] >> 28) | ((int) (pt[j + 7] << 14) >> 10);
				Z[i + 11] = (int) (pt[j + 7] >> 18) | ((int) (pt[j + 8] << 24) >> 10);
				Z[i + 12] = ((int) pt[j + 8] << 2) >> 10;
				Z[i + 13] = (int) (pt[j + 8] >> 30) | ((int) (pt[j + 9] << 12) >> 10);
				Z[i + 14] = (int) (pt[j + 9] >> 20) | ((int) (pt[j + 10] << 22) >> 10);
				Z[i + 15] = (int) pt[j + 10] >> 10;
				j += 11;
			}

			Buffer.BlockCopy(signature, signatureOffset + ((Parameter.N_III_P * (Parameter.B_BIT_III_P + 1)) / Const.BYTE_SIZE), C, 0, Polynomial.HASH);

		}
	}
}
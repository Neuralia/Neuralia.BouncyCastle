namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {

	internal class Polynomial {

		/// <summary>
		///     Size of A Random Number (in Byte)
		/// </summary>
		public const int RANDOM = 32;

		/// <summary>
		///     Size of A Seed (in Byte)
		/// </summary>
		public const int SEED = 32;

		/// <summary>
		///     Size of Hash Value C (in Byte) in the Signature Package
		/// </summary>
		public const int HASH = 32;

		/// <summary>
		///     Size of Hashed Message
		/// </summary>
		public const int MESSAGE = 64;

		/// <summary>
		///     Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-1.
		///     Z is A Polynomial Bounded by B and C is the Output of A Hashed String
		/// </summary>
		public static readonly int SIGNATURE_I = (((Parameter.N_I * (Parameter.B_BIT_I+1)) + 7) / 8) + HASH;

		/// <summary>
		///     Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-3 (Option for Speed).
		///     Z is A Polynomial Bounded by B and C is the Output of A Hashed String
		/// </summary>
		public static readonly int SIGNATURE_III = (((Parameter.N_III * (Parameter.B_BIT_III+1)) + 7) / 8) + HASH;

		/// <summary>
		///     Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-3 (Option for Speed).
		///     Z is A Polynomial Bounded by B and C is the Output of A Hashed String
		/// </summary>
		public static readonly int SIGNATURE_V = (((Parameter.N_V * (Parameter.B_BIT_V+1)) + 7) / 8) + HASH;
		
		/// <summary>
		///     Size of the Signature Package (Z, C) (in Byte) for Heuristic qTESLA Security Category-3 (Option for Speed).
		///     Z is A Polynomial Bounded by B and C is the Output of A Hashed String
		/// </summary>
		public static readonly int SIGNATURE_V_SIZE = (((Parameter.N_V_SIZE * (Parameter.B_BIT_V_SIZE+1)) + 7) / 8) + HASH;
		
		/// <summary>
		///     Size of the Signature Package (Z, C) (in Byte) for Provably-Secure qTESLA Security Category-1.
		///     Z is A Polynomial Bounded by B and C is the Output of A Hashed String
		/// </summary>
		public static readonly int SIGNATURE_I_P = (((Parameter.N_I_P * (Parameter.B_BIT_I_P+1)) + 7) / 8) + HASH;

		/// <summary>
		///     Size of the Signature Package (Z, C) (in Byte) for Provably-Secure qTESLA Security Category-3.
		///     Z is A Polynomial Bounded by B and C is the Output of A Hashed String
		/// </summary>
		public static readonly int SIGNATURE_III_P = (((Parameter.N_III_P * (Parameter.B_BIT_III_P+1)) + 7) / 8) + HASH;

		/// <summary>
		///     Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-1
		/// </summary>
		public static readonly int PUBLIC_KEY_I = (((Parameter.N_I * Parameter.Q_LOGARITHM_I) + 7) / 8) + SEED;

		/// <summary>
		///     Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-3 (Option
		///     for Speed)
		/// </summary>
		public static readonly int PUBLIC_KEY_III_SPEED = (((Parameter.N_III * Parameter.K_III * Parameter.Q_LOGARITHM_III) + 7) / 8) + SEED;

		/// <summary>
		///     Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-3 (Option
		///     for Size)
		/// </summary>
		public static readonly int PUBLIC_KEY_V = (((Parameter.N_V * Parameter.K_V * Parameter.Q_LOGARITHM_V) + 7) / 8) + SEED;
		
		/// <summary>
		///     Size of the Public Key (in Byte) Containing seedA and Polynomial T for Heuristic qTESLA Security Category-3 (Option
		///     for Size)
		/// </summary>
		public static readonly int PUBLIC_KEY_V_SIZE = (((Parameter.N_V_SIZE * Parameter.K_V_SIZE * Parameter.Q_LOGARITHM_V_SIZE) + 7) / 8) + SEED;
		
		/// <summary>
		///     Size of the Public Key (in Byte) Containing seedA and Polynomial T for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public static readonly int PUBLIC_KEY_I_P = (((Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P) + 7) / 8) + SEED;

		/// <summary>
		///     Size of the Public Key (in Byte) Containing seedA and Polynomial T for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public static readonly int PUBLIC_KEY_III_P = (((Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P) + 7) / 8) + SEED;

		/// <summary>
		///     Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA
		///     and seedY)
		///     for Heuristic qTESLA Security Category-1
		/// </summary>
		public static readonly int PRIVATE_KEY_I = (((Parameter.N_I * Parameter.S_BIT_I) / (sizeof(sbyte) * 8)) * 2) + (SEED * 2);

		/// <summary>
		///     Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA
		///     and seedY)
		///     for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public static readonly int PRIVATE_KEY_III = (((Parameter.N_III * Parameter.S_BIT_III) / (sizeof(sbyte) * 8)) * 2) + (SEED * 2);

		/// <summary>
		///     Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA
		///     and seedY)
		///     for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public static readonly int PRIVATE_KEY_V = (((Parameter.N_V * Parameter.S_BIT_V) / (sizeof(sbyte) * 8)) * 2) + (SEED * 2);

		/// <summary>
		///     Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA
		///     and seedY)
		///     for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public static readonly int PRIVATE_KEY_V_SIZE = (((Parameter.N_V_SIZE * Parameter.S_BIT_V_SIZE) / (sizeof(sbyte) * 8)) * 2) + (SEED * 2);

		
		/// <summary>
		///     Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA
		///     and seedY)
		///     for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public static readonly int PRIVATE_KEY_I_P = Parameter.N_I_P + (Parameter.N_I_P * Parameter.K_I_P) + (SEED * 2);

		/// <summary>
		///     Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA
		///     and seedY)
		///     for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public static readonly int PRIVATE_KEY_III_P = Parameter.N_III_P + (Parameter.N_III_P * Parameter.K_III_P) + (SEED * 2);

		/// <summary>
		///     **************************************************************************
		///     Description:	Montgomery Reduction for Heuristic qTESLA Security Category 1
		///     and Security Category-3 (Option for Size and Speed)
		/// </summary>
		/// <param name="number">        Number to be Reduced </param>
		/// <param name="q">            Modulus </param>
		/// <param name="qInverse">
		/// </param>
		/// <returns>
		///     Reduced Number
		///     ***************************************************************************
		/// </returns>
		private static int montgomery(long number, int q, long qInverse) {

			return (int) ((number + (((number * qInverse) & 0xFFFFFFFFL) * q)) >> 32);

		}

		/// <summary>
		///     **************************************************************************
		///     Description:	Montgomery Reduction for Provably-Secure qTESLA
		///     Security Category-1 and Security Category-3
		/// </summary>
		/// <param name="number">        Number to be Reduced </param>
		/// <param name="q">            Modulus </param>
		/// <param name="qInverse">
		/// </param>
		/// <returns>
		///     Reduced Number
		///     ***************************************************************************
		/// </returns>
		private static long montgomeryP(long number, int q, long qInverse) {

			return (number + (((number * qInverse) & 0xFFFFFFFFL) * q)) >> 32;

		}

		/// <summary>
		///     ********************************************************************************************
		///     Description:	Barrett Reduction for Heuristic qTESLA Security Category-3
		///     (Option for Size or Speed)
		/// </summary>
		/// <param name="number">                    Number to be Reduced </param>
		/// <param name="barrettMultiplication"> </param>
		/// <param name="barrettDivision"> </param>
		/// <param name="q">
		///     Modulus
		/// </param>
		/// <returns>
		///     Reduced Number
		///     *********************************************************************************************
		/// </returns>
		public static int barrett(int number, int q, int barrettMultiplication, int barrettDivision) {

			return number - ((int) (((long) number * barrettMultiplication) >> barrettDivision) * q);

		}

		/// <summary>
		///     ***********************************************************************************************
		///     Description:	Barrett Reduction for Provably-Secure qTESLA Security Category-1 and
		///     Security Category-3
		/// </summary>
		/// <param name="number">                    Number to be Reduced </param>
		/// <param name="barrettMultiplication"> </param>
		/// <param name="barrettDivision"> </param>
		/// <param name="q">
		///     Modulus
		/// </param>
		/// <returns>
		///     Reduced Number
		///     ************************************************************************************************
		/// </returns>
		public static long barrett(long number, int q, int barrettMultiplication, int barrettDivision) {

			return number - (((number * barrettMultiplication) >> barrettDivision) * q);

		}

		/// <summary>
		///     **********************************************************************************************************
		///     Description:	Forward Number Theoretic Transform for Heuristic qTESLA Security Category-1,
		///     Security Category-3 (Option for Size and Speed)
		/// </summary>
		/// <param name="destination">        Destination of Transformation </param>
		/// <param name="source">            Source of Transformation </param>
		/// <param name="n">                Polynomial Degree </param>
		/// <param name="q">                Modulus </param>
		/// <param name="qInverse">
		/// </param>
		/// <returns>
		///     none
		///     ***********************************************************************************************************
		/// </returns>
		private static void numberTheoreticTransform(int[] destination, int[] source, int n, int q, long qInverse) {

			int jTwiddle        = 0;
			int numberOfProblem = n >> 1;

			for(; numberOfProblem > 0; numberOfProblem >>= 1) {

				int j = 0;
				int jFirst;

				for(jFirst = 0; jFirst < n; jFirst = j + numberOfProblem) {

					long omega = source[jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						int temporary = montgomery(omega * destination[j + numberOfProblem], q, qInverse);

						destination[j + numberOfProblem] = destination[j] - temporary;
						destination[j]                   = destination[j] + temporary;

					}

				}

			}

		}

		/// <summary>
		///     ************************************************************************************************************
		///     Description:	Forward Number Theoretic Transform for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="destination">        Destination of Transformation </param>
		/// <param name="source">
		///     Source of Transformation
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************
		/// </returns>
		private static void numberTheoreticTransformIP(long[] destination, long[] source) {

			int numberOfProblem = Parameter.N_I_P >> 1;
			int jTwiddle        = 0;

			for(; numberOfProblem > 0; numberOfProblem >>= 1) {

				int j = 0;
				int jFirst;

				for(jFirst = 0; jFirst < Parameter.N_I_P; jFirst = j + numberOfProblem) {

					long omega = source[jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						long temporary = montgomeryP(omega * destination[j + numberOfProblem], Parameter.Q_I_P, Parameter.Q_INVERSE_I_P);

						destination[j + numberOfProblem] = destination[j] + (Parameter.Q_I_P - temporary);

						destination[j] = destination[j] + temporary;

					}

				}

			}

		}

		/// <summary>
		///     ************************************************************************************************************
		///     Description:	Forward Number Theoretic Transform for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="destination">        Destination of Transformation </param>
		/// <param name="source">
		///     Source of Transformation
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************
		/// </returns>
		private static void numberTheoreticTransformIIIP(long[] destination, long[] source) {

			int jTwiddle        = 0;
			int numberOfProblem = Parameter.N_III_P >> 1;

			for(; numberOfProblem > 0; numberOfProblem >>= 1) {

				int j = 0;
				int jFirst;

				for(jFirst = 0; jFirst < Parameter.N_III_P; jFirst = j + numberOfProblem) {

					int omega = (int) source[jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						long temporary = barrett(montgomeryP(omega * destination[j + numberOfProblem], Parameter.Q_III_P, Parameter.Q_INVERSE_III_P), Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P);

						destination[j + numberOfProblem] = barrett(destination[j] + ((2L * Parameter.Q_III_P) - temporary), Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P);

						destination[j] = barrett(destination[j] + temporary, Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P);

					}

				}

			}

		}

		/// <summary>
		///     ****************************************************************************************************************
		///     Description:	Inverse Number Theoretic Transform for Heuristic qTESLA Security Category-1
		/// </summary>
		/// <param name="destination">            Destination of Inverse Transformation </param>
		/// <param name="source">
		///     Source of Inverse Transformation
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************
		/// </returns>
		private static void inverseNumberTheoreticTransformI(int[] destination, int[] source) {

			int jTwiddle = 0;

			for(int numberOfProblem = 1; numberOfProblem < Parameter.N_I; numberOfProblem *= 2) {

				int j = 0;
				int jFirst;

				for(jFirst = 0; jFirst < Parameter.N_I; jFirst = j + numberOfProblem) {

					long omega = source[jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						int temporary = destination[j];

						destination[j] = temporary + destination[j + numberOfProblem];

						destination[j + numberOfProblem] = montgomery(omega * (temporary - destination[j + numberOfProblem]), Parameter.Q_I, Parameter.Q_INVERSE_I);

					}

				}

			}

			for(int i = 0; i < (Parameter.N_I / 2); i++) {

				destination[i] = montgomery((long) Parameter.R_I * destination[i], Parameter.Q_I, Parameter.Q_INVERSE_I);

			}

		}

		/// <summary>
		///     ************************************************************************************************************************************************************************
		///     Description:	Inverse Number Theoretic Transform for Heuristic qTESLA Security Category-3 (Option for Size and
		///     Speed)
		/// </summary>
		/// <param name="destination">                    Destination of Inverse Transformation </param>
		/// <param name="source">                        Source of Inverse Transformation </param>
		/// <param name="n">                            Polynomial Degree </param>
		/// <param name="q">                            Modulus </param>
		/// <param name="qInverse"> </param>
		/// <param name="r"> </param>
		/// <param name="barrettMultiplication"> </param>
		/// <param name="barrettDivision">
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************************************************
		/// </returns>
		private static void inverseNumberTheoreticTransform(int[] destination, int[] source, int n, int q, long qInverse, int r, int barrettMultiplication, int barrettDivision) {

			int jTwiddle = 0;

			for(int numberOfProblem = 1; numberOfProblem < n; numberOfProblem *= 2) {

				int j = 0;

				for(int jFirst = 0; jFirst < n; jFirst = j + numberOfProblem) {

					long omega = source[jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						int temporary = destination[j];

						if(numberOfProblem == 16) {

							destination[j] = barrett(temporary + destination[j + numberOfProblem], q, barrettMultiplication, barrettDivision);

						} else {

							destination[j] = temporary + destination[j + numberOfProblem];

						}

						destination[j + numberOfProblem] = montgomery(omega * (temporary - destination[j + numberOfProblem]), q, qInverse);

					}

				}

			}

			for(int i = 0; i < (n / 2); i++) {

				destination[i] = montgomery((long) r * destination[i], q, qInverse);

			}

		}

		/// <summary>
		///     *********************************************************************************************************************************************************************************
		///     Description:	Inverse Number Theoretic Transform for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="destination">            Destination of Inverse Transformation </param>
		/// <param name="destinationOffset">    Starting Point of the Destination </param>
		/// <param name="source">                Source of Inverse Transformation </param>
		/// <param name="sourceOffset">
		///     Starting Point of the Source
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************************************************************************
		/// </returns>
		private static void inverseNumberTheoreticTransformIP(long[] destination, int destinationOffset, long[] source, int sourceOffset) {

			int jTwiddle = 0;

			for(int numberOfProblem = 1; numberOfProblem < Parameter.N_I_P; numberOfProblem *= 2) {

				int j = 0;
				int jFirst;

				for(jFirst = 0; jFirst < Parameter.N_I_P; jFirst = j + numberOfProblem) {

					long omega = source[sourceOffset + jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						long temporary = destination[destinationOffset + j];

						destination[destinationOffset + j] = temporary + destination[destinationOffset + j + numberOfProblem];

						destination[destinationOffset + j + numberOfProblem] = montgomeryP(omega * (temporary + ((2L * Parameter.Q_I_P) - destination[destinationOffset + j + numberOfProblem])), Parameter.Q_I_P, Parameter.Q_INVERSE_I_P);

					}

				}

				numberOfProblem *= 2;

				for(jFirst = 0; jFirst < Parameter.N_I_P; jFirst = j + numberOfProblem) {

					long omega = source[sourceOffset + jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						long temporary = destination[destinationOffset + j];

						destination[destinationOffset + j] = barrett(temporary + destination[destinationOffset + j + numberOfProblem], Parameter.Q_I_P, Parameter.BARRETT_MULTIPLICATION_I_P, Parameter.BARRETT_DIVISION_I_P);

						destination[destinationOffset + j + numberOfProblem] = montgomeryP(omega * (temporary + ((2L * Parameter.Q_I_P) - destination[destinationOffset + j + numberOfProblem])), Parameter.Q_I_P, Parameter.Q_INVERSE_I_P);

					}

				}

			}

		}

		/// <summary>
		///     ****************************************************************************************************************************************************************************************
		///     Description:	Inverse Number Theoretic Transform for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="destination">            Destination of Inverse Transformation </param>
		/// <param name="destinationOffset">    Starting Point of the Destination </param>
		/// <param name="source">                Source of Inverse Transformation </param>
		/// <param name="sourceOffset">
		///     Starting Point of the Source
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************************************************
		/// </returns>
		private static void inverseNumberTheoreticTransformIIIP(long[] destination, int destinationOffset, long[] source, int sourceOffset) {

			int jTwiddle = 0;

			for(int numberOfProblem = 1; numberOfProblem < Parameter.N_III_P; numberOfProblem *= 2) {

				int j = 0;
				int jFirst;

				for(jFirst = 0; jFirst < Parameter.N_III_P; jFirst = j + numberOfProblem) {

					long omega = source[sourceOffset + jTwiddle++];

					for(j = jFirst; j < (jFirst + numberOfProblem); j++) {

						long temporary = destination[destinationOffset + j];

						destination[destinationOffset + j] = barrett(temporary + destination[destinationOffset + j + numberOfProblem], Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P);

						destination[destinationOffset + j + numberOfProblem] = barrett(montgomeryP(omega * (temporary + ((2L * Parameter.Q_III_P) - destination[destinationOffset + j + numberOfProblem])), Parameter.Q_III_P, Parameter.Q_INVERSE_III_P), Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P);

					}

				}

			}

		}

		/// <summary>
		///     **************************************************************************************************************************************************
		///     Description:	Component Wise Polynomial Multiplication for Heuristic qTESLA Security Category-1 and Security
		///     Category-3 (Option for Size and Speed)
		/// </summary>
		/// <param name="product">                    Product = Multiplicand (*) Multiplier </param>
		/// <param name="multiplicand">            Multiplicand Array </param>
		/// <param name="multiplier">                Multiplier Array </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="q">                        Modulus </param>
		/// <param name="qInverse">
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************************************************************************************
		/// </returns>
		private static void componentWisePolynomialMultiplication(int[] product, int[] multiplicand, int[] multiplier, int n, int q, long qInverse) {

			for(int i = 0; i < n; i++) {

				product[i] = montgomery((long) multiplicand[i] * multiplier[i], q, qInverse);

			}

		}

		/// <summary>
		///     ****************************************************************************************************************************************************************************************************************
		///     Description:	Component Wise Polynomial Multiplication for Provably-Secure qTESLA Security Category-1 and Security
		///     Category-3
		/// </summary>
		/// <param name="product">                    Product = Multiplicand (*) Multiplier </param>
		/// <param name="productOffset">            Starting Point of the Product Array </param>
		/// <param name="multiplicand">            Multiplicand Array </param>
		/// <param name="multiplicandOffset">        Starting Point of the Multiplicand Array </param>
		/// <param name="multiplier">                Multiplier Array </param>
		/// <param name="multiplierOffset">        Starting Point of the Multiplier Array </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="q">                        Modulus </param>
		/// <param name="qInverse">
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************************************************************************
		/// </returns>
		private static void componentWisePolynomialMultiplication(long[] product, int productOffset, long[] multiplicand, int multiplicandOffset, long[] multiplier, int multiplierOffset, int n, int q, long qInverse) {

			for(int i = 0; i < n; i++) {

				product[productOffset + i] = montgomeryP(multiplicand[multiplicandOffset + i] * multiplier[multiplierOffset + i], q, qInverse);

			}

		}

		/// <summary>
		///     *********************************************************************************************************************************************
		///     Description:	Polynomial Number Theoretic Transform for Provably-Secure qTESLA Security Category-1 and Category-3
		/// </summary>
		/// <param name="arrayNumberTheoreticTransform">        Transformed Array </param>
		/// <param name="array">                                Array to be Transformed </param>
		/// <param name="n">
		///     Polynomial Degree
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************************************
		/// </returns>
		public static void polynomialNumberTheoreticTransform(long[] arrayNumberTheoreticTransform, long[] array, int n) {

			for(int i = 0; i < n; i++) {

				arrayNumberTheoreticTransform[i] = array[i];

			}

			if(n == Parameter.N_I_P) {

				numberTheoreticTransformIP(arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_I_P);

			}

			if(n == Parameter.N_III_P) {

				numberTheoreticTransformIIIP(arrayNumberTheoreticTransform, PolynomialProvablySecure.ZETA_III_P);

			}

		}

		/// <summary>
		///     *****************************************************************************************************************************************
		///     Description:	Polynomial Multiplication for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size and
		///     Speed)
		/// </summary>
		/// <param name="product">                    Product = Multiplicand * Multiplier </param>
		/// <param name="multiplicand">            Multiplicand Array </param>
		/// <param name="multiplier">                Multiplier Array </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="q">                        Modulus </param>
		/// <param name="qInverse"> </param>
		/// <param name="zeta">
		/// </param>
		/// <returns>
		///     none
		///     ******************************************************************************************************************************************
		/// </returns>
		public static void polynomialMultiplication(int[] product, int[] multiplicand, int[] multiplier, int n, int q, long qInverse, int[] zeta) {

			int[] multiplierNumberTheoreticTransform = new int[n];

			for(int i = 0; i < n; i++) {

				multiplierNumberTheoreticTransform[i] = multiplier[i];

			}

			numberTheoreticTransform(multiplierNumberTheoreticTransform, zeta, n, q, qInverse);

			componentWisePolynomialMultiplication(product, multiplicand, multiplierNumberTheoreticTransform, n, q, qInverse);

			if(q == Parameter.Q_I) {

				inverseNumberTheoreticTransformI(product, PolynomialHeuristic.ZETA_INVERSE_I);

			}


			if(q == Parameter.Q_III) {

				inverseNumberTheoreticTransform(product, PolynomialHeuristic.ZETA_INVERSE_III, Parameter.N_III, Parameter.Q_III, Parameter.Q_INVERSE_III, Parameter.R_III, Parameter.BARRETT_MULTIPLICATION_III, Parameter.BARRETT_DIVISION_III);

			}

			if(q == Parameter.Q_V) {

				inverseNumberTheoreticTransform(product, PolynomialHeuristic.ZETA_INVERSE_V, Parameter.N_V, Parameter.Q_V, Parameter.Q_INVERSE_V, Parameter.R_V, Parameter.BARRETT_MULTIPLICATION_V, Parameter.BARRETT_DIVISION_V);

			}
		}

		/// <summary>
		///     *************************************************************************************************************************************************************************************************
		///     Description:	Polynomial Multiplication for Provably-Secure qTESLA Security Category-1 and Category-3
		/// </summary>
		/// <param name="product">                    Product = Multiplicand * Multiplier </param>
		/// <param name="productOffset">            Starting Point of the Product Array </param>
		/// <param name="multiplicand">            Multiplicand Array </param>
		/// <param name="multiplicandOffset">        Starting Point of the Multiplicand Array </param>
		/// <param name="multiplier">                Multiplier Array </param>
		/// <param name="multiplierOffset">        Starting Point of the Multiplier Array </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="q">                        Modulus </param>
		/// <param name="qInverse">
		/// </param>
		/// <returns>
		///     none
		///     **************************************************************************************************************************************************************************************************
		/// </returns>
		public static void polynomialMultiplication(long[] product, int productOffset, long[] multiplicand, int multiplicandOffset, long[] multiplier, int multiplierOffset, int n, int q, long qInverse) {

			componentWisePolynomialMultiplication(product, productOffset, multiplicand, multiplicandOffset, multiplier, multiplierOffset, n, q, qInverse);

			if(q == Parameter.Q_I_P) {

				inverseNumberTheoreticTransformIP(product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_I_P, 0);

			}

			if(q == Parameter.Q_III_P) {

				inverseNumberTheoreticTransformIIIP(product, productOffset, PolynomialProvablySecure.ZETA_INVERSE_III_P, 0);

			}

		}

		/// <summary>
		///     **************************************************************************************************************************************************
		///     Description:	Polynomial Addition for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size or Speed)
		///     Q + L_E
		///     < 2 ^ (CEIL ( LOGARITHM ( Q, 2)))
		///         No Necessary Reduction for Y + SC
		/// </summary>
		/// <param name="summation">            Summation = Augend + Addend </param>
		/// <param name="augend">                Augend Array </param>
		/// <param name="addend">                Addend Array </param>
		/// <param name="n">
		///     Polynomial Degree
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************************************************************************************
		/// </returns>
		public static void polynomialAddition(int[] summation, int[] augend, int[] addend, int n) {

			for(int i = 0; i < n; i++) {

				summation[i] = augend[i] + addend[i];

			}

		}

		/// <summary>
		///     ******************************************************************************************************************************************************
		///     Description:	Polynomial Addition for Provably-Secure qTESLA Security Category-1 and Category-3
		///     Q + L_E
		///     < 2 ^ (CEIL ( LOGARITHM ( Q, 2)))
		///         No Necessary Reduction for Y + SC
		/// </summary>
		/// <param name="summation">            Summation = Augend + Addend </param>
		/// <param name="summationOffset">        Starting Point of the Summation Array </param>
		/// <param name="augend">                Augend Array </param>
		/// <param name="augendOffset">        Starting Point of the Augend Array </param>
		/// <param name="addend">                Addend Array </param>
		/// <param name="addendOffset">        Starting Point of the Addend Array </param>
		/// <param name="n">
		///     Polynomial Degree
		/// </param>
		/// <returns>
		///     none
		///     *******************************************************************************************************************************************************
		/// </returns>
		public static void polynomialAddition(long[] summation, int summationOffset, long[] augend, int augendOffset, long[] addend, int addendOffset, int n) {

			for(int i = 0; i < n; i++) {

				summation[summationOffset + i] = augend[augendOffset + i] + addend[addendOffset + i];

			}

		}

		/// <summary>
		///     ***********************************************************************************************************
		///     Description:	Polynomial Addition with Correction for Heuristic qTESLA Security Category-1 and Category-3
		///     (Option for Size or Speed)
		///     Q + L_E
		///     < 2 ^ (CEIL ( LOGARITHM ( Q, 2)))
		///         No Necessary Reduction for Y + SC
		/// </summary>
		/// <param name="summation">            Summation = Augend + Addend </param>
		/// <param name="augend">                Augend Array </param>
		/// <param name="addend">                Addend Array </param>
		/// <param name="n">
		///     Polynomial Degree
		/// </param>
		/// <returns>
		///     none
		///     ***********************************************************************************************************
		/// </returns>
		public static void polynomialAdditionCorrection(int[] summation, int[] augend, int[] addend, int n, int q) {

			for(int i = 0; i < n; i++) {

				summation[i] = augend[i] + addend[i];
				/* If summation[i] < 0 Then Add Q */
				summation[i] += (summation[i] >> 31) & q;
				summation[i] -= q;
				/* If summation[i] >= Q Then Subtract Q */
				summation[i] += (summation[i] >> 31) & q;

			}

		}

		/// <summary>
		///     ********************************************************************************************************************
		///     Description:	Polynomial Subtraction with Correction for Heuristic qTESLA Security Category-1 and Security
		///     Category-3
		///     (Option for Size or Speed)
		/// </summary>
		/// <param name="difference">                    Difference = Minuend (-) Subtrahend </param>
		/// <param name="minuend">                        Minuend Array </param>
		/// <param name="subtrahend">                    Subtrahend Array </param>
		/// <param name="n">                            Polynomial Degree </param>
		/// <param name="q">
		///     Modulus
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************
		/// </returns>
		public static void polynomialSubtractionCorrection(int[] difference, int[] minuend, int[] subtrahend, int n, int q) {

			for(int i = 0; i < n; i++) {

				difference[i] = minuend[i] - subtrahend[i];
				/* If difference[i] < 0 Then Add Q */
				difference[i] += (difference[i] >> 31) & q;

			}

		}

		/// <summary>
		///     *****************************************************************************************************************************************
		///     Description:	Polynomial Subtraction with Montgomery Reduction for Heuristic qTESLA Security Category-1 and Security
		///     Category-3
		///     (Option for Size or Speed)
		/// </summary>
		/// <param name="difference">                    Difference = Minuend (-) Subtrahend </param>
		/// <param name="minuend">                        Minuend Array </param>
		/// <param name="subtrahend">                    Subtrahend Array </param>
		/// <param name="n">                            Polynomial Degree </param>
		/// <param name="q">                            Modulus </param>
		/// <param name="qInverse"> </param>
		/// <param name="r">
		/// </param>
		/// <returns>
		///     none
		///     ******************************************************************************************************************************************
		/// </returns>
		public static void polynomialSubtractionMontgomery(int[] difference, int[] minuend, int[] subtrahend, int n, int q, long qInverse, int r) {

			for(int i = 0; i < n; i++) {

				difference[i] = montgomery((long) r * (minuend[i] - subtrahend[i]), q, qInverse);

			}

		}

		/// <summary>
		///     ****************************************************************************************************************************************************************************************************************************
		///     Description:	Polynomial Subtraction for Provably-Secure qTESLA Security Category-1 and Security Category-3
		/// </summary>
		/// <param name="difference">                    Difference = Minuend (-) Subtrahend </param>
		/// <param name="differenceOffset">            Starting Point of the Difference Array </param>
		/// <param name="minuend">                        Minuend Array </param>
		/// <param name="minuendOffset">                Starting Point of the Minuend Array </param>
		/// <param name="subtrahend">                    Subtrahend Array </param>
		/// <param name="subtrahendOffset">            Starting Point of the Subtrahend Array </param>
		/// <param name="n">                            Polynomial Degree </param>
		/// <param name="q">                            Modulus </param>
		/// <param name="barrettMultiplication"> </param>
		/// <param name="barrettDivision">
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************************************************************************************
		/// </returns>
		public static void polynomialSubtraction(long[] difference, int differenceOffset, long[] minuend, int minuendOffset, long[] subtrahend, int subtrahendOffset, int n, int q, int barrettMultiplication, int barrettDivision) {

			for(int i = 0; i < n; i++) {

				difference[differenceOffset + i] = barrett(minuend[minuendOffset + i] - subtrahend[subtrahendOffset + i], q, barrettMultiplication, barrettDivision);

			}

		}

		/// <summary>
		///     ****************************************************************************************************************************************************************************
		///     Description:	Generation of Polynomial A for Heuristic qTESLA Security Category-1 and Security Category-3 (Option
		///     for Size or Speed)
		/// </summary>
		/// <param name="A">                                    Polynomial to be Generated </param>
		/// <param name="seed">                                Kappa-Bit Seed </param>
		/// <param name="seedOffset">                            Starting Point of the Kappa-Bit Seed </param>
		/// <param name="n">                                    Polynomial Degree </param>
		/// <param name="q">                                    Modulus </param>
		/// <param name="qInverse"> </param>
		/// <param name="qLogarithm">
		///     q <= 2 ^ qLogarithm </param>
		/// <param name="generatorA"> </param>
		/// <param name="inverseNumberTheoreticTransform">
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************************************
		/// </returns>
		public static void polynomialUniform(int[] A, sbyte[] seed, int seedOffset, int n, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform) {

			int   position        = 0;
			int   i               = 0;
			int   numberOfByte    = (qLogarithm + 7) / 8;
			int   numberOfBlock   = generatorA;
			short dualModeSampler = 0;
			int   value1;
			int   value2;
			int   value3;
			int   value4;
			int   mask = (1 << qLogarithm) - 1;

			sbyte[] buffer = new sbyte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * generatorA];

			HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * generatorA, dualModeSampler++, seed, seedOffset, RANDOM);

			while(i < n) {

				if(position > ((HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock) - (((sizeof(int) * 8) / (sizeof(sbyte) * 8)) * numberOfByte))) {

					numberOfBlock = 1;

					HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock, dualModeSampler++, seed, seedOffset, RANDOM);

					position = 0;

				}

				value1   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				value2   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				value3   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				value4   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				if((value1 < q) && (i < n)) {

					A[i++] = montgomery((long) value1 * inverseNumberTheoreticTransform, q, qInverse);

				}

				if((value2 < q) && (i < n)) {

					A[i++] = montgomery((long) value2 * inverseNumberTheoreticTransform, q, qInverse);

				}

				if((value3 < q) && (i < n)) {

					A[i++] = montgomery((long) value3 * inverseNumberTheoreticTransform, q, qInverse);

				}

				if((value4 < q) && (i < n)) {

					A[i++] = montgomery((long) value4 * inverseNumberTheoreticTransform, q, qInverse);

				}

			}

		}

		/// <summary>
		///     ************************************************************************************************************************************************************************************
		///     Description:	Generation of Polynomial A for Provably-Secure qTESLA Security Category-1 and Security Category-3
		/// </summary>
		/// <param name="A">                                    Polynomial to be Generated </param>
		/// <param name="seed">                                Kappa-Bit Seed </param>
		/// <param name="seedOffset">                            Starting Point of the Kappa-Bit Seed </param>
		/// <param name="n">                                    Polynomial Degree </param>
		/// <param name="k">                                    Number of Ring-Learning-With-Errors Samples </param>
		/// <param name="q">                                    Modulus </param>
		/// <param name="qInverse"> </param>
		/// <param name="qLogarithm">
		///     q <= 2 ^ qLogarithm </param>
		/// <param name="generatorA"> </param>
		/// <param name="inverseNumberTheoreticTransform">
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************************************************************
		/// </returns>
		public static void polynomialUniform(long[] A, sbyte[] seed, int seedOffset, int n, int k, int q, long qInverse, int qLogarithm, int generatorA, int inverseNumberTheoreticTransform) {

			int   position        = 0;
			int   i               = 0;
			int   numberOfByte    = (qLogarithm + 7) / 8;
			int   numberOfBlock   = generatorA;
			short dualModeSampler = 0;
			int   value1;
			int   value2;
			int   value3;
			int   value4;
			int   mask = (1 << qLogarithm) - 1;

			sbyte[] buffer = new sbyte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock];

			HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock, dualModeSampler++, seed, seedOffset, RANDOM);

			while(i < (n * k)) {

				if(position > ((HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock) - (((sizeof(int) * 8) / (sizeof(sbyte) * 8)) * numberOfByte))) {

					numberOfBlock = 1;

					HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock, dualModeSampler++, seed, seedOffset, RANDOM);

					position = 0;

				}

				value1   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				value2   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				value3   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				value4   =  CommonFunction.load32(buffer, position) & mask;
				position += numberOfByte;

				if((value1 < q) && (i < (n * k))) {

					A[i++] = montgomeryP((long) value1 * inverseNumberTheoreticTransform, q, qInverse);

				}

				if((value2 < q) && (i < (n * k))) {

					A[i++] = montgomeryP((long) value2 * inverseNumberTheoreticTransform, q, qInverse);

				}

				if((value3 < q) && (i < (n * k))) {

					A[i++] = montgomeryP((long) value3 * inverseNumberTheoreticTransform, q, qInverse);

				}

				if((value4 < q) && (i < (n * k))) {

					A[i++] = montgomeryP((long) value4 * inverseNumberTheoreticTransform, q, qInverse);

				}

			}

		}

		/// <summary>
		///     ************************************************************************************************************************************************************
		///     Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for
		///     Heuristic qTESLA Security Category-1 and
		///     SecurityCategory-3 (Option for Size or Speed)
		/// </summary>
		/// <param name="product">                Product of Two Polynomials </param>
		/// <param name="privateKey">            Part of the Private Key </param>
		/// <param name="positionList">        List of Indices of Non-Zero Elements in C </param>
		/// <param name="signList">            List of Signs of Non-Zero Elements in C </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="h">
		///     Number of Non-Zero Entries of Output Elements of Encryption
		/// </param>
		/// <returns>
		///     none
		///     *************************************************************************************************************************************************************
		/// </returns>
		public static void sparsePolynomialMultiplication16(int[] product, short[] privateKey, int[] positionList, short[] signList, int n, int h) {

			int position;

			ArraysExtensions.Fill(product, 0);

			for(int i = 0; i < h; i++) {

				position = positionList[i];

				for(int j = 0; j < position; j++) {

					product[j] -= signList[i] * privateKey[(n + j) - position];

				}

				for(int j = position; j < n; j++) {

					product[j] += signList[i] * privateKey[j - position];

				}

			}

		}

		/// <summary>
		///     ***************************************************************************************************************************************************************************************************
		///     Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for
		///     Provably-Secure qTESLA Security Category-1 and Category-3
		/// </summary>
		/// <param name="product">                Product of Two Polynomials </param>
		/// <param name="productOffset">        Starting Point of the Product of Two Polynomials </param>
		/// <param name="privateKey">            Part of the Private Key </param>
		/// <param name="privateKeyOffset">    Starting Point of the Private Key </param>
		/// <param name="positionList">        List of Indices of Non-Zero Elements in C </param>
		/// <param name="signList">            List of Signs of Non-Zero Elements in C </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="h">
		///     Number of Non-Zero Entries of Output Elements of Encryption
		/// </param>
		/// <returns>
		///     none
		///     *****************************************************************************************************************************************************************************************************
		/// </returns>
		public static void sparsePolynomialMultiplication8(long[] product, int productOffset, sbyte[] privateKey, int privateKeyOffset, int[] positionList, short[] signList, int n, int h) {

			int position;

			ArraysExtensions.Fill(product, 0L);

			for(int i = 0; i < h; i++) {

				position = positionList[i];

				for(int j = 0; j < position; j++) {

					product[productOffset + j] -= signList[i] * privateKey[(privateKeyOffset + n + j) - position];

				}

				for(int j = position; j < n; j++) {

					product[productOffset + j] += signList[i] * privateKey[(privateKeyOffset + j) - position];

				}

			}

		}

		/// <summary>
		///     *********************************************************************************************************************************************************
		///     Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for
		///     Heuristic qTESLA Security Category-1 and
		///     Security Category-3 (Option for Size or Speed)
		/// </summary>
		/// <param name="product">                    Product of Two Polynomials </param>
		/// <param name="publicKey">                Part of the Public Key </param>
		/// <param name="positionList">            List of Indices of Non-Zero Elements in C </param>
		/// <param name="signList">                List of Signs of Non-Zero Elements in C </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="h">
		///     Number of Non-Zero Entries of Output Elements of Encryption
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************************************************
		/// </returns>
		public static void sparsePolynomialMultiplication32(int[] product, int[] publicKey, int[] positionList, short[] signList, int n, int h) {

			int position;

			ArraysExtensions.Fill(product, 0);

			for(int i = 0; i < h; i++) {

				position = positionList[i];

				for(int j = 0; j < position; j++) {

					product[j] -= signList[i] * publicKey[(n + j) - position];

				}

				for(int j = position; j < n; j++) {

					product[j] += signList[i] * publicKey[j - position];

				}

			}

		}

		/// <summary>
		///     *********************************************************************************************************************************************************************************************************************************************************
		///     Description:	Performs Sparse Polynomial Multiplication for A Value Needed During Message Signification for
		///     Provably-Secure qTESLA Security Category-1 and Security Category-3
		/// </summary>
		/// <param name="product">                    Product of Two Polynomials </param>
		/// <param name="productOffset">            Starting Point of the Product of Two Polynomials </param>
		/// <param name="publicKey">                Part of the Public Key </param>
		/// <param name="publicKeyOffset">            Starting Point of the Public Key </param>
		/// <param name="positionList">            List of Indices of Non-Zero Elements in C </param>
		/// <param name="signList">                List of Signs of Non-Zero Elements in C </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="h">                        Number of Non-Zero Entries of Output Elements of Encryption </param>
		/// <param name="q">                        Modulus </param>
		/// <param name="barrettMultiplication"> </param>
		/// <param name="barrettDivision">
		/// </param>
		/// <returns>
		///     none
		///     **********************************************************************************************************************************************************************************************************************************************************
		/// </returns>
		public static void sparsePolynomialMultiplication32(long[] product, int productOffset, int[] publicKey, int publicKeyOffset, int[] positionList, short[] signList, int n, int h, int q, int barrettMultiplication, int barrettDivision) {

			int position;

			ArraysExtensions.Fill(product, 0L);

			for(int i = 0; i < h; i++) {

				position = positionList[i];

				for(int j = 0; j < position; j++) {

					product[productOffset + j] -= signList[i] * publicKey[(publicKeyOffset + n + j) - position];

				}

				for(int j = position; j < n; j++) {

					product[productOffset + j] += signList[i] * publicKey[(publicKeyOffset + j) - position];

				}

			}

			for(int i = 0; i < n; i++) {

				product[productOffset + i] = barrett(product[productOffset + i], q, barrettMultiplication, barrettDivision);

			}

		}
	}
}
namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {
	internal sealed class Parameter {

		// taken from here: https://github.com/qtesla/qTesla/tree/master/Reference_implementation
		/// <summary>
		///     Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int N_I = 512;

		/// <summary>
		///     Dimension, (Dimension - 1) is the Polynomial Degree for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int N_I_P = 1024;

		/// <summary>
		///     Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int N_III = 1024;
		
		/// <summary>
		///     Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int N_V = 2048;
		
		/// <summary>
		///     Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int N_V_SIZE = 2048;

		/// <summary>
		///     Dimension, (Dimension - 1) is the Polynomial Degree for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int N_III_P = 2048;

		/// <summary>
		///     N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int N_LOGARITHM_I = 9;

		/// <summary>
		///     N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int N_LOGARITHM_I_P = 10;

		/// <summary>
		///     N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int N_LOGARITHM_III = 10;
		
		/// <summary>
		///     N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int N_LOGARITHM_V = 11;
		
		/// <summary>
		///     N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int N_LOGARITHM_V_SIZE = 11;

		/// <summary>
		///     N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int N_LOGARITHM_III_P = 11;

		/// <summary>
		///     Modulus for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int Q_I = 4205569;

		/// <summary>
		///     Modulus for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int Q_I_P = 343576577;

		/// <summary>
		///     Modulus for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int Q_III = 8404993;
		
		/// <summary>
		///     Modulus for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int Q_V = 16801793;
		
		/// <summary>
		///     Modulus for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int Q_V_SIZE = 33564673;

		/// <summary>
		///     Modulus for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int Q_III_P = 856145921;

		/// <summary>
		///     Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int Q_LOGARITHM_I = 23;

		/// <summary>
		///     Q <= 2 ^ Q_LOGARITHM for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int Q_LOGARITHM_I_P = 29;

		/// <summary>
		///     Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int Q_LOGARITHM_III = 24;
		
		/// <summary>
		///     Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int Q_LOGARITHM_V = 25;
		
		/// <summary>
		///     Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int Q_LOGARITHM_V_SIZE = 26;

		/// <summary>
		///     Q <= 2 ^ Q_LOGARITHM for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int Q_LOGARITHM_III_P = 30;

		public const long Q_INVERSE_I         = 3098553343L;
		public const long Q_INVERSE_I_P       = 2205847551L;
		public const long Q_INVERSE_III = 4034936831L;
		public const long Q_INVERSE_V  = 3707789311L;
		public const long Q_INVERSE_V_SIZE  = 4223674367L;
		public const long Q_INVERSE_III_P     = 587710463L;

		/// <summary>
		///     B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int B_I = 1048575;

		/// <summary>
		///     B Determines the Interval the Randomness is Chosen in During Signing for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int B_I_P = 524287;

		/// <summary>
		///     B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3
		///     (Option for Speed)
		/// </summary>
		public const int B_III = 2097151;
		
		/// <summary>
		///     B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3
		///     (Option for Size)
		/// </summary>
		public const int B_V = 4194303;
	
		/// <summary>
		///     B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3
		///     (Option for Size)
		/// </summary>
		public const int B_V_SIZE = ((1 << B_BIT_V_SIZE) - 1);

		/// <summary>
		///     B Determines the Interval the Randomness is Chosen in During Signing for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int B_III_P = 2097151;

		/// <summary>
		///     B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int B_BIT_I = 20;

		/// <summary>
		///     B = 2 ^ B_BIT - 1 for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int B_BIT_I_P = 19;

		/// <summary>
		/// <summary>
		///     B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int B_BIT_III = 21;
		
		/// <summary>
		///     B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int B_BIT_V = 22;
			
		/// <summary>
		///     B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int B_BIT_V_SIZE = 23;

		/// <summary>
		///     B = 2 ^ B_BIT - 1 for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int B_BIT_III_P = 21;

		public const int S_BIT_I         = 9;
		public const int S_BIT_I_P       = 8;
		public const int S_BIT_III = 9;
		public const int S_BIT_V  = 9;
		public const int S_BIT_V_SIZE  = 9;
		public const int S_BIT_III_P     = 8;

		/// <summary>
		///     Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int K_I = 1;

		/// <summary>
		///     Number of Ring-Learning-With-Errors Samples for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int K_I_P = 4;

		/// <summary>
		///     Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int K_III = 1;
		
		/// <summary>
		///     Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int K_V = 1;
		
		/// <summary>
		///     Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int K_V_SIZE = 1;

		/// <summary>
		///     Number of Ring-Learning-With-Errors Samples for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int K_III_P = 5;

		/// <summary>
		///     Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int H_I = 30;

		/// <summary>
		///     Number of Non-Zero Entries of Output Elements of Encryption for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int H_I_P = 25;

		/// <summary>
		///     Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for
		///     Speed)
		/// </summary>
		public const int H_III = 48;
		
		/// <summary>
		///     Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for
		///     Size)
		/// </summary>
		public const int H_V = 61;
			
		/// <summary>
		///     Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for
		///     Size)
		/// </summary>
		public const int H_V_SIZE = 77;

		/// <summary>
		///     Number of Non-Zero Entries of Output Elements of Encryption for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int H_III_P = 40;

		/// <summary>
		///     Number of Rounded Bits for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int D_I = 21;

		/// <summary>
		///     Number of Rounded Bits for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int D_I_P = 22;

		/// <summary>
		///     Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int D_III = 22;
		
		/// <summary>
		///     Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int D_V = 23;
		
		/// <summary>
		///     Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int D_V_SIZE = 24;

		/// <summary>
		///     Number of Rounded Bits for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int D_III_P = 24;

		/// <summary>
		///     Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_I = 1586;

		/// <summary>
		///     Bound in Checking Error Polynomial for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_I_P = 554;

		/// <summary>
		///     Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_III = 1147;
		
		/// <summary>
		///     Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_V = 1554;
		
		/// <summary>
		///     Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_V_SIZE = 1792;

		/// <summary>
		///     Bound in Checking Error Polynomial for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_III_P = 901;

		public const int REJECTION_I         = KEY_GENERATOR_BOUND_E_I;
		public const int REJECTION_I_P       = KEY_GENERATOR_BOUND_E_I_P;
		public const int REJECTION_III = KEY_GENERATOR_BOUND_E_III;
		public const int REJECTION_V  = KEY_GENERATOR_BOUND_E_V;
		public const int REJECTION_V_SIZE  = (2*KEY_GENERATOR_BOUND_E_V_SIZE);
		public const int REJECTION_III_P     = KEY_GENERATOR_BOUND_E_III_P;

		/// <summary>
		///     Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_I = 1586;

		/// <summary>
		///     Bound in Checking Secret Polynomial for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_I_P = 554;

		/// <summary>
		///     Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_III = 1233;
		
		/// <summary>
		///     Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_V = 1554;
		
		/// <summary>
		///     Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_V_SIZE = 1792;

		/// <summary>
		///     Bound in Checking Secret Polynomial for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_III_P = 901;

		public const int U_I         = KEY_GENERATOR_BOUND_S_I;
		public const int U_I_P       = KEY_GENERATOR_BOUND_S_I_P;
		public const int U_III = KEY_GENERATOR_BOUND_S_III;
		public const int U_V  = KEY_GENERATOR_BOUND_S_V;
		public const int U_V_SIZE  = (2*KEY_GENERATOR_BOUND_S_V_SIZE);
		public const int U_III_P     = KEY_GENERATOR_BOUND_S_III_P;

		/// <summary>
		///     Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-1
		/// </summary>
		public const double SIGMA_I = 22.93;

		/// <summary>
		///     Standard Deviation of Centered Discrete Gaussian Distribution for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const double SIGMA_I_P = 8.5;

		/// <summary>
		///     Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for
		///     Speed)
		/// </summary>
		public const double SIGMA_III = 10.2;
		
		/// <summary>
		///     Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for
		///     Size)
		/// </summary>
		public const double SIGMA_V = 10.2;
		
		/// <summary>
		///     Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for
		///     Size)
		/// </summary>
		public const double SIGMA_V_SIZE = 10.2;

		/// <summary>
		///     Standard Deviation of Centered Discrete Gaussian Distribution for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const double SIGMA_III_P = 8.5;

		public const double SIGMA_E_I         = SIGMA_I;
		public const double SIGMA_E_I_P       = SIGMA_I_P;
		public const double SIGMA_E_III = SIGMA_III;
		public const double SIGMA_E_V  = SIGMA_V;
		public const double SIGMA_E_V_SIZE  = SIGMA_V_SIZE;
		public const double SIGMA_E_III_P     = SIGMA_III_P;

		/// <summary>
		///     XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-1
		/// </summary>
		public const double XI_I = 27;

		/// <summary>
		///     XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const double XI_I_P = 10;
		/// <summary>
		///     XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for
		///     Speed)
		/// </summary>
		public const double XI_III = 12;
		
		/// <summary>
		///     XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for
		///     Size)
		/// </summary>
		public const double XI_V = 12;
		
		/// <summary>
		///     XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for
		///     Size)
		/// </summary>
		public const double XI_V_SIZE = 0;

		/// <summary>
		///     XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const double XI_III_P = 10;

		public const int BARRETT_MULTIPLICATION_I         = 1021;
		public const int BARRETT_MULTIPLICATION_I_P       = 3;
		public const int BARRETT_MULTIPLICATION_III = 511;
		public const int BARRETT_MULTIPLICATION_V  = 255;
		public const int BARRETT_MULTIPLICATION_V_SIZE  = 127;
		public const int BARRETT_MULTIPLICATION_III_P     = 5;

		public const int BARRETT_DIVISION_I         = 32;
		public const int BARRETT_DIVISION_I_P       = 30;
		public const int BARRETT_DIVISION_III = 32;
		public const int BARRETT_DIVISION_V  = 32;
		public const int BARRETT_DIVISION_V_SIZE  = 32;
		public const int BARRETT_DIVISION_III_P     = 32;

		/// <summary>
		///     The Number of Blocks Requested in the First Extendable-Output Function Call
		///     for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int GENERATOR_A_I = 19;

		/// <summary>
		///     The Number of Blocks Requested in the First Extendable-Output Function Call
		///     for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int GENERATOR_A_I_P = 108;


		/// <summary>
		///     The Number of Blocks Requested in the First Extendable-Output Function Call
		///     for Provably-Secure qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int GENERATOR_A_III = 38;
		
		/// <summary>
		///     The Number of Blocks Requested in the First Extendable-Output Function Call
		///     for Provably-Secure qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int GENERATOR_A_V = 98;
		
		/// <summary>
		///     The Number of Blocks Requested in the First Extendable-Output Function Call
		///     for Provably-Secure qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int GENERATOR_A_V_SIZE = 73;

		/// <summary>
		///     The Number of Blocks Requested in the First Extendable-Output Function Call
		///     for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int GENERATOR_A_III_P = 180;

		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_I         = 113307;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_I_P       = 13632409;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_III = 237839;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_V  = 6863778;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_V_SIZE  = 22253546;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P     = 513161157;

		public const int R_I         = 1081347;
		public const int R_III = 15873;
		public const int R_V  = 10510081;
		public const int R_V_SIZE  = 32253825;
		public const int R_I_P  = 172048372;
		public const int R_III_P  = 14237691;
	}
}
using System;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {
	internal class CommonFunction {

		/// <summary>
		///     **************************************************************************************************
		///     Description:	Checks Whether the Two Parts of Arrays are Equal to Each Other
		/// </summary>
		/// <param name="left">            Left Array </param>
		/// <param name="leftOffset">        Starting Point of the Left Array </param>
		/// <param name="right">            Right Array </param>
		/// <param name="rightOffset">        Starting Point of the Right Array </param>
		/// <param name="length">
		///     Length to be Compared from the Starting Point
		/// </param>
		/// <returns>
		///     true            Equal
		///     false			Different
		///     ***************************************************************************************************
		/// </returns>
		public static bool memoryEqual(sbyte[] left, int leftOffset, sbyte[] right, int rightOffset, int length) {

			if(((leftOffset + length) <= left.Length) && ((rightOffset + length) <= right.Length)) {

				for(int i = 0; i < length; i++) {

					if(left[leftOffset + i] != right[rightOffset + i]) {

						return false;

					}

				}

				return true;

			}

			return false;

		}

		/// <summary>
		///     **************************************************************************
		///     Description:	Converts 2 Consecutive Bytes in "load" to A Number of "Short"
		///     from A Known Position
		/// </summary>
		/// <param name="load">            Source Array </param>
		/// <param name="loadOffset">
		///     Starting Position
		/// </param>
		/// <returns>
		///     A Number of "Short"
		///     ***************************************************************************
		/// </returns>
		public static short load16(sbyte[] load, int loadOffset) {

			short number = 0;

			if((load.Length - loadOffset) >= (Const.SHORT_SIZE / Const.BYTE_SIZE)) {

				number ^= (short) ((short)  (load[loadOffset + 0] & 0xFF) << (Const.BYTE_SIZE * 0));
				number ^= (short) ((short)  (load[loadOffset + 1] & 0xFF) << (Const.BYTE_SIZE * 1));

			} else {

				for(int i = 0; i < (load.Length - loadOffset); i++) {

					number ^= (short) ((short) (load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i));

				}

			}

			return number;

		}

		/// <summary>
		///     ****************************************************************************
		///     Description:	Converts 4 Consecutive Bytes in "load" to A Number of "Integer"
		///     from A Known Position
		/// </summary>
		/// <param name="load">            Source Array </param>
		/// <param name="loadOffset">
		///     Starting Position
		/// </param>
		/// <returns>
		///     A Number of "Integer"
		///     *****************************************************************************
		/// </returns>
		public static int load32(sbyte[] load, int loadOffset) {

			int number = 0;

			if((load.Length - loadOffset) >= (Const.INT_SIZE / Const.BYTE_SIZE)) {

				number ^= (int) (load[loadOffset + 0] & 0xFF) << (Const.BYTE_SIZE * 0);
				number ^= (int) (load[loadOffset + 1] & 0xFF) << (Const.BYTE_SIZE * 1);
				number ^= (int) (load[loadOffset + 2] & 0xFF) << (Const.BYTE_SIZE * 2);
				number ^= (int) (load[loadOffset + 3] & 0xFF) << (Const.BYTE_SIZE * 3);

			} else {

				for(int i = 0; i < (load.Length - loadOffset); i++) {

					number ^= (load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

				}

			}

			return number;

		}

		/// <summary>
		///     *************************************************************************
		///     Description:	Converts 8 Consecutive Bytes in "load" to A Number of "Long"
		///     from A Known Position
		/// </summary>
		/// <param name="load">            Source Array </param>
		/// <param name="loadOffset">
		///     Starting Position
		/// </param>
		/// <returns>
		///     A Number of "Long"
		///     **************************************************************************
		/// </returns>
		public static long load64(sbyte[] load, int loadOffset) {

			long number = 0L;

			if((load.Length - loadOffset) >= (Const.LONG_SIZE / Const.BYTE_SIZE)) {

				number ^= (long) (load[loadOffset + 0] & 0xFF) << (Const.BYTE_SIZE * 0);
				number ^= (long) (load[loadOffset + 1] & 0xFF) << (Const.BYTE_SIZE * 1);
				number ^= (long) (load[loadOffset + 2] & 0xFF) << (Const.BYTE_SIZE * 2);
				number ^= (long) (load[loadOffset + 3] & 0xFF) << (Const.BYTE_SIZE * 3);
				number ^= (long) (load[loadOffset + 4] & 0xFF) << (Const.BYTE_SIZE * 4);
				number ^= (long) (load[loadOffset + 5] & 0xFF) << (Const.BYTE_SIZE * 5);
				number ^= (long) (load[loadOffset + 6] & 0xFF) << (Const.BYTE_SIZE * 6);
				number ^= (long) (load[loadOffset + 7] & 0xFF) << (Const.BYTE_SIZE * 7);
			} else {

				for(int i = 0; i < (load.Length - loadOffset); i++) {

					number ^= (long) (load[loadOffset + i] & 0xFF) << (Const.BYTE_SIZE * i);

				}

			}

			return number;

		}

		/// <summary>
		///     ***************************************************************************
		///     Description:	Converts A Number of "Short" to 2 Consecutive Bytes in "store"
		///     from a known position
		/// </summary>
		/// <param name="store">            Destination Array </param>
		/// <param name="storeOffset">        Starting position </param>
		/// <param name="number">
		///     Source Number
		/// </param>
		/// <returns>
		///     none
		///     ****************************************************************************
		/// </returns>
		public static void store16(sbyte[] store, int storeOffset, short number) {

			if((store.Length - storeOffset) >= (Const.SHORT_SIZE / Const.BYTE_SIZE)) {

				store[storeOffset + 0] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 0)) & 0xFF));
				store[storeOffset + 1] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 1)) & 0xFF));

			} else {

				for(int i = 0; i < (store.Length - storeOffset); i++) {

					store[storeOffset + i] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * i)) & 0xFF));

				}

			}

		}

		/// <summary>
		///     *****************************************************************************
		///     Description:	Converts A Number of "Integer" to 4 Consecutive Bytes in "store"
		///     from A Known Position
		/// </summary>
		/// <param name="store">            Destination Array </param>
		/// <param name="storeOffset">        Starting Position </param>
		/// <param name="number">
		///     :			Source Number
		/// </param>
		/// <returns>
		///     none
		///     ******************************************************************************
		/// </returns>
		public static void store32(sbyte[] store, int storeOffset, int number) {

			if((store.Length - storeOffset) >= (Const.INT_SIZE / Const.BYTE_SIZE)) {

				store[storeOffset + 0] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 0)) & 0xFF));
				store[storeOffset + 1] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 1)) & 0xFF));
				store[storeOffset + 2] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 2)) & 0xFF));
				store[storeOffset + 3] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 3)) & 0xFF));

			} else {

				for(int i = 0; i < (store.Length - storeOffset); i++) {

					store[storeOffset + i] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * i)) & 0xFF));

				}

			}

		}

		/// <summary>
		///     **************************************************************************
		///     Description:	Converts A Number of "Long" to 8 Consecutive Bytes in "store"
		///     from A Known Position
		/// </summary>
		/// <param name="store">            Destination Array </param>
		/// <param name="storeOffset">        Starting Position </param>
		/// <param name="number">
		///     Source Number
		/// </param>
		/// <returns>
		///     none
		///     ***************************************************************************
		/// </returns>
		public static void store64(sbyte[] store, int storeOffset, long number) {

			if((store.Length - storeOffset) >= (Const.LONG_SIZE / Const.BYTE_SIZE)) {

				store[storeOffset + 0] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 0)) & 0xFFL));
				store[storeOffset + 1] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 1)) & 0xFFL));
				store[storeOffset + 2] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 2)) & 0xFFL));
				store[storeOffset + 3] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 3)) & 0xFFL));
				store[storeOffset + 4] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 4)) & 0xFFL));
				store[storeOffset + 5] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 5)) & 0xFFL));
				store[storeOffset + 6] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 6)) & 0xFFL));
				store[storeOffset + 7] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * 7)) & 0xFFL));

			} else {

				for(int i = 0; i < (store.Length - storeOffset); i++) {

					store[storeOffset + i] = unchecked((sbyte) ((number >> (Const.BYTE_SIZE * i)) & 0xFFL));

				}

			}

		}
	}
}
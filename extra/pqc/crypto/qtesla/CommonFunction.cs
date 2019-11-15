using System;
using Neuralia.Blockchains.Tools.Serialization;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.qtesla {
	internal unsafe class CommonFunction {

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

				return left.AsSpan().Slice(leftOffset, length).SequenceEqual(right.AsSpan().Slice(rightOffset, length));
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

			if(load.Length <= loadOffset) {
				return number;
			}
			fixed(sbyte* ptr = load.AsSpan().Slice(loadOffset, load.Length - loadOffset)) {
				
				TypeSerializer.Deserialize((byte*)ptr, out  number);
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
			if(load.Length <= loadOffset) {
				return number;
			}
			fixed(sbyte* ptr = load.AsSpan().Slice(loadOffset, load.Length - loadOffset)) {
				
				TypeSerializer.Deserialize((byte*)ptr, out  number);
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

			long number = 0;
			if(load.Length <= loadOffset) {
				return number;
			}
			fixed(sbyte* ptr = load.AsSpan().Slice(loadOffset, load.Length - loadOffset)) {
				
				TypeSerializer.Deserialize((byte*)ptr, out  number);
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

			if(store.Length <= storeOffset) {
				return;
			}
			fixed(sbyte* ptr = store.AsSpan().Slice(storeOffset, store.Length - storeOffset)) {
				
				TypeSerializer.Serialize(number, (byte*)ptr);
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

			if(store.Length <= storeOffset) {
				return;
			}
			fixed(sbyte* ptr = store.AsSpan().Slice(storeOffset, store.Length - storeOffset)) {
				
				TypeSerializer.Serialize(number, (byte*)ptr);
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

			if(store.Length <= storeOffset) {
				return;
			}
			fixed(sbyte* ptr = store.AsSpan().Slice(storeOffset, store.Length - storeOffset)) {
				
				TypeSerializer.Serialize(number, (byte*)ptr);
			}

		}
	}
}
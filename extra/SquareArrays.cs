using Neuralia.Blockchains.Tools.Data.Allocation;

namespace Neuralia.BouncyCastle.extra {
	public static class SquareArrays {
		public static MemoryBlockDoubleArray ReturnRectangularbyteArray3(int size1, int size2) {
			MemoryBlockDoubleArray doubleBlock = MemoryAllocators.Instance.doubleArrayCryptoAllocator.Take(size1);

			for(int array1 = 0; array1 < size1; array1++) {
				doubleBlock[array1] = MemoryAllocators.Instance.cryptoAllocator.Take(size2);
			}

			return doubleBlock;
		}

		public static byte[][] ReturnRectangularbyteArray(int size1, int size2) {
			byte[][] newArray = new byte[size1][];

			for(int array1 = 0; array1 < size1; array1++) {
				newArray[array1] = new byte[size2];
			}

			return newArray;
		}

		public static int[][] ReturnRectangularIntArray(int size1, int size2) {
			int[][] newArray = new int[size1][];

			for(int array1 = 0; array1 < size1; array1++) {
				newArray[array1] = new int[size2];
			}

			return newArray;
		}

		public static long[][] ReturnRectangularLongArray(int size1, int size2) {
			long[][] newArray = new long[size1][];

			for(int array1 = 0; array1 < size1; array1++) {
				newArray[array1] = new long[size2];
			}

			return newArray;
		}
	}

}
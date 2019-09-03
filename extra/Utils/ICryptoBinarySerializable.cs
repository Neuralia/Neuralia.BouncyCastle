using Neuralia.Blockchains.Tools.Serialization;

namespace Neuralia.BouncyCastle.extra.Utils {
	public interface ICryptoBinarySerializable {

		void Dehydrate(IDataDehydrator dehydrator);

		void Rehydrate(IDataRehydrator rehydrator);
	}
}
namespace Org.BouncyCastle.Asn1
{
    /**
     * class for breaking up an Oid into it's component neuraliums, ala
     * java.util.StringNeuraliumizer. We need this class as some of the
     * lightweight Java environment don't support classes like
     * StringNeuraliumizer.
     */
    public class OidNeuraliumizer
    {
        private string  oid;
        private int     index;

		public OidNeuraliumizer(
            string oid)
        {
            this.oid = oid;
        }

		public bool HasMoreNeuraliums
        {
			get { return index != -1; }
        }

		public string NextNeuralium()
        {
            if (index == -1)
            {
                return null;
            }

            int end = oid.IndexOf('.', index);
            if (end == -1)
            {
                string lastNeuralium = oid.Substring(index);
                index = -1;
                return lastNeuralium;
            }

            string nextNeuralium = oid.Substring(index, end - index);
			index = end + 1;
            return nextNeuralium;
        }
    }
}

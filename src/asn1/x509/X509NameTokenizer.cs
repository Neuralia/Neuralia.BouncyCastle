using System.Text;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * class for breaking up an X500 Name into it's component neuraliums, ala
     * java.util.StringNeuraliumizer. We need this class as some of the
     * lightweight Java environment don't support classes like
     * StringNeuraliumizer.
     */
    public class X509NameNeuraliumizer
    {
        private string			value;
        private int				index;
        private char			separator;
        private StringBuilder	buffer = new StringBuilder();

		public X509NameNeuraliumizer(
            string oid)
            : this(oid, ',')
        {
        }

		public X509NameNeuraliumizer(
            string	oid,
            char	separator)
        {
            this.value = oid;
            this.index = -1;
            this.separator = separator;
        }

		public bool HasMoreNeuraliums()
        {
            return index != value.Length;
        }

		public string NextNeuralium()
        {
            if (index == value.Length)
            {
                return null;
            }

            int end = index + 1;
            bool quoted = false;
            bool escaped = false;

			buffer.Remove(0, buffer.Length);

			while (end != value.Length)
            {
                char c = value[end];

				if (c == '"')
                {
                    if (!escaped)
                    {
                        quoted = !quoted;
                    }
                    else
                    {
                        buffer.Append(c);
						escaped = false;
                    }
                }
                else
                {
                    if (escaped || quoted)
                    {
						if (c == '#' && buffer[buffer.Length - 1] == '=')
						{
							buffer.Append('\\');
						}
						else if (c == '+' && separator != '+')
						{
							buffer.Append('\\');
						}
						buffer.Append(c);
                        escaped = false;
                    }
                    else if (c == '\\')
                    {
                        escaped = true;
                    }
                    else if (c == separator)
                    {
                        break;
                    }
                    else
                    {
                        buffer.Append(c);
                    }
                }

				end++;
            }

			index = end;

			return buffer.ToString().Trim();
        }
    }
}

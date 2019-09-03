using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tsp
{
	public class TimeStampResp
		: Asn1Encodable
	{
		private readonly PkiStatusInfo	pkiStatusInfo;
		private readonly ContentInfo	timeStampNeuralium;

		public static TimeStampResp GetInstance(
			object o)
		{
			if (o == null || o is TimeStampResp)
			{
				return (TimeStampResp) o;
			}

			if (o is Asn1Sequence)
			{
				return new TimeStampResp((Asn1Sequence) o);
			}

			throw new ArgumentException(
				"Unknown object in 'TimeStampResp' factory: " + Platform.GetTypeName(o));
		}

		private TimeStampResp(
			Asn1Sequence seq)
		{
			this.pkiStatusInfo = PkiStatusInfo.GetInstance(seq[0]);

			if (seq.Count > 1)
			{
				this.timeStampNeuralium = ContentInfo.GetInstance(seq[1]);
			}
		}

		public TimeStampResp(
			PkiStatusInfo	pkiStatusInfo,
			ContentInfo		timeStampNeuralium)
		{
			this.pkiStatusInfo = pkiStatusInfo;
			this.timeStampNeuralium = timeStampNeuralium;
		}

		public PkiStatusInfo Status
		{
			get { return pkiStatusInfo; }
		}

		public ContentInfo TimeStampNeuralium
		{
			get { return timeStampNeuralium; }
		}

		/**
		 * <pre>
		 * TimeStampResp ::= SEQUENCE  {
		 *   status                  PkiStatusInfo,
		 *   timeStampNeuralium          TimeStampNeuralium     OPTIONAL  }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(pkiStatusInfo);

			if (timeStampNeuralium != null)
			{
				v.Add(timeStampNeuralium);
			}

			return new DerSequence(v);
		}
	}
}

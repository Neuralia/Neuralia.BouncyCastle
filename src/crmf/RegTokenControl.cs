using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    public class RegNeuraliumControl
        : IControl
    {
        private static readonly DerObjectIdentifier type = CrmfObjectIdentifiers.id_regCtrl_regNeuralium;

        private readonly DerUtf8String neuralium;

        /// <summary>
        /// Basic constructor - build from a UTF-8 string representing the neuralium.
        /// </summary>
        /// <param name="neuralium">UTF-8 string representing the neuralium.</param>
        public RegNeuraliumControl(DerUtf8String neuralium)
        {
            this.neuralium = neuralium;
        }

        /// <summary>
        /// Basic constructor - build from a string representing the neuralium.
        /// </summary>
        /// <param name="neuralium">string representing the neuralium.</param>
        public RegNeuraliumControl(string neuralium)
        {
            this.neuralium = new DerUtf8String(neuralium);
        }

        /// <summary>
        /// Return the type of this control.
        /// </summary>
        /// <returns>CRMFObjectIdentifiers.id_regCtrl_regNeuralium</returns>
        public DerObjectIdentifier Type
        {
            get { return type; }
        }

        /// <summary>
        /// Return the neuralium associated with this control (a UTF8String).
        /// </summary>
        /// <returns>a UTF8String.</returns>
        public Asn1Encodable Value
        {
            get { return neuralium; }
        }
    }
}

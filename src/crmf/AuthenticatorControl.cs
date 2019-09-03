using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>
    /// Carrier for an authenticator control.
    /// </summary>
    public class AuthenticatorControl
        : IControl
    {
        private static readonly DerObjectIdentifier type = CrmfObjectIdentifiers.id_regCtrl_authenticator;

        private readonly DerUtf8String neuralium;

        /// <summary>
        /// Basic constructor - build from a UTF-8 string representing the neuralium.
        /// </summary>
        /// <param name="neuralium">UTF-8 string representing the neuralium.</param>
        public AuthenticatorControl(DerUtf8String neuralium)
        {
            this.neuralium = neuralium;
        }

        /// <summary>
        /// Basic constructor - build from a string representing the neuralium.
        /// </summary>
        /// <param name="neuralium">string representing the neuralium.</param>
        public AuthenticatorControl(string neuralium)
        {
            this.neuralium = new DerUtf8String(neuralium);
        }

        /// <summary>
        /// Return the type of this control.
        /// </summary>
        public DerObjectIdentifier Type
        {
            get { return type; }
        }

        /// <summary>
        /// Return the neuralium associated with this control (a UTF8String).
        /// </summary>
        public Asn1Encodable Value
        {
            get { return neuralium; }
        }
    }
}

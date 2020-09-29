using System;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.Chacha {
	/// <summary>
	/// Implementation of Daniel J. Bernstein's ChaCha stream cipher.
	/// </summary>
	public class ChaCha7539Engine2
            : Salsa20Engine2
        {
            /// <summary>
            /// Creates a 20 rounds ChaCha engine.
            /// </summary>
            public ChaCha7539Engine2(int rounds)
                : base(rounds)
            {
            }
    
            public override string AlgorithmName
            {
                get { return "ChaCha7539"; }
            }
    
            protected override int NonceSize
            {
                get { return 12; }
            }
    
            protected override void AdvanceCounter()
            {
                if (++engineState[12] == 0)
                    throw new InvalidOperationException("attempt to increase counter past 2^32.");
            }
    
            protected override void ResetCounter()
            {
                engineState[12] = 0;
            }
    
            protected override void SetKey(ByteArray keyBytes, ByteArray ivBytes)
            {
                if (keyBytes != null)
                {
                    if (keyBytes.Length != 32)
                        throw new ArgumentException(AlgorithmName + " requires 256 bit key");
    
                    PackTauOrSigma(keyBytes.Length, engineState, 0);
    
                    // Key
                    Pack.LE_To_UInt32(keyBytes.Bytes, keyBytes.Offset, engineState, 4, 8);
                }
    
                // IV
                Pack.LE_To_UInt32(ivBytes.Bytes, ivBytes.Offset, engineState, 13, 3);
            }
    
            protected override void GenerateKeyStream(ByteArray output)
            {
                ChaChaEngine2.ChachaCore(rounds, engineState, x);
                Pack.UInt32_To_LE(x, output.Bytes, output.Offset);
            }
        }
}
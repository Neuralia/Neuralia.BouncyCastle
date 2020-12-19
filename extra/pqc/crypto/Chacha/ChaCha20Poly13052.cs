using System;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Neuralia.BouncyCastle.extra.pqc.crypto.Chacha;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.Chacha {
	public class ChaCha20Poly13052
        : IAeadCipher
    {
        private enum State
        {
            Uninitialized  = 0,
            EncInit        = 1,
            EncAad         = 2,
            EncData        = 3,
            EncFinal       = 4,
            DecInit        = 5,
            DecAad         = 6,
            DecData        = 7,
            DecFinal       = 8,
        }

        private const int BufSize = 64;
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int MacSize = 16;
        private static readonly ByteArray Zeroes = ByteArray.Create(MacSize - 1);

        private const ulong AadLimit = ulong.MaxValue;
        private const ulong DataLimit = ((1UL << 32) - 1) * 64;

        private readonly ChaCha7539Engine2 mChacha20;
        private readonly Poly130522 mPoly1305;

        private readonly ByteArray mKey = ByteArray.Create(KeySize);
        private readonly ByteArray mNonce = ByteArray.Create(NonceSize);
        private readonly ByteArray mBuf = ByteArray.Create(BufSize + MacSize);
        private readonly ByteArray mMac = ByteArray.Create(MacSize);

        private ByteArray mInitialAad;

        private ulong mAadCount;
        private ulong mDataCount;
        private State mState = State.Uninitialized;
        private int mBufPos;

        public ChaCha20Poly13052(int rounds)
        {
            this.mPoly1305 = new Poly130522();
            if (MacSize != this.mPoly1305.GetMacSize())
                throw new ArgumentException("must be a 128-bit MAC", "poly1305");

            this.mChacha20 = new ChaCha7539Engine2(rounds);
        }


        public virtual string AlgorithmName
        {
            get { return "ChaCha20Poly1305"; }
        }

        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            KeyParameter2 initKeyParam;
            ByteArray initNonce;
            ICipherParameters chacha20Params;

            if (parameters is AeadParameters2)
            {
                AeadParameters2 aeadParams = (AeadParameters2)parameters;

                int macSizeBits = aeadParams.MacSize;
                if ((MacSize * 8) != macSizeBits)
                    throw new ArgumentException("Invalid value for MAC size: " + macSizeBits);

                initKeyParam = aeadParams.Key;
                initNonce = aeadParams.GetNonce();
                chacha20Params = new ParametersWithIV2(initKeyParam, initNonce);

                this.mInitialAad = aeadParams.GetAssociatedText();
            }
            else if (parameters is ParametersWithIV2)
            {
                ParametersWithIV2 ivParams = (ParametersWithIV2)parameters;

                initKeyParam = (KeyParameter2)ivParams.Parameters;
                initNonce = ivParams.GetIV();
                chacha20Params = ivParams;

                this.mInitialAad = null;
            }
            else
            {
                throw new ArgumentException("invalid parameters passed to ChaCha20Poly1305", "parameters");
            }

            // Validate key
            if (null == initKeyParam)
            {
                if (State.Uninitialized == mState)
                    throw new ArgumentException("Key must be specified in initial init");
            }
            else
            {
                if (KeySize != initKeyParam.GetKey().Length)
                    throw new ArgumentException("Key must be 256 bits");
            }

            // Validate nonce
            if (null == initNonce || NonceSize != initNonce.Length)
                throw new ArgumentException("Nonce must be 96 bits");

            // Check for encryption with reused nonce
            if (State.Uninitialized != mState && forEncryption && mNonce == initNonce)
            {
                if (null == initKeyParam || mKey == initKeyParam.GetKey())
                    throw new ArgumentException("cannot reuse nonce for ChaCha20Poly1305 encryption");
            }

            if (null != initKeyParam)
            {
                initKeyParam.GetKey().CopyTo(mKey);
            }

            initNonce.CopyTo(mNonce);

            mChacha20.Init(true, chacha20Params);

            this.mState = forEncryption ? State.EncInit : State.DecInit;

            Reset(true, false);
        }

        public virtual int GetOutputSize(int len)
        {
            int total = System.Math.Max(0, len) + mBufPos;

            switch (mState)
            {
            case State.DecInit:
            case State.DecAad:
            case State.DecData:
                return System.Math.Max(0, total - MacSize);
            case State.EncInit:
            case State.EncAad:
            case State.EncData:
                return total + MacSize;
            default:
                throw new InvalidOperationException();
            }
        }

        public virtual int GetUpdateOutputSize(int len)
        {
            int total = System.Math.Max(0, len) + mBufPos;

            switch (mState)
            {
            case State.DecInit:
            case State.DecAad:
            case State.DecData:
                total = System.Math.Max(0, total - MacSize);
                break;
            case State.EncInit:
            case State.EncAad:
            case State.EncData:
                break;
            default:
                throw new InvalidOperationException();
            }

            return total - (total % BufSize);
        }

        public virtual void ProcessAadByte(byte input)
        {
            CheckAad();

            this.mAadCount = IncrementCount(mAadCount, 1, AadLimit);
            mPoly1305.Update(input);
        }
        
        public int ProcessByte(byte input, byte[] outBytes, int outOff) {
            return ProcessByte(input, ByteArray.Wrap(outBytes), outOff);
        }

        public int ProcessBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff) {
            return ProcessBytes(ByteArray.Wrap(inBytes), inOff, len, ByteArray.Wrap(outBytes), outOff);
        }

        public int DoFinal(byte[] outBytes, int outOff) {
            return DoFinal(ByteArray.Wrap(outBytes), outOff);
        }
        
        public void ProcessAadBytes(byte[] inBytes, int inOff, int len) {
            ProcessAadBytes(ByteArray.Wrap(inBytes), inOff, len);
        }

        public virtual void ProcessAadBytes(ByteArray inBytes, int inOff, int len)
        {
            if (null == inBytes)
                throw new ArgumentNullException("inBytes");
            if (inOff < 0)
                throw new ArgumentException("cannot be negative", "inOff");
            if (len < 0)
                throw new ArgumentException("cannot be negative", "len");
            
            if (len > (inBytes.Length - inOff))
                throw new DataLengthException("input buffer too short");

            CheckAad();

            if (len > 0)
            {
                this.mAadCount = IncrementCount(mAadCount, (uint)len, AadLimit);
                mPoly1305.BlockUpdate(inBytes, inOff, len);
            }
        }

        public virtual int ProcessByte(byte input, ByteArray outBytes, int outOff)
        {
            CheckData();

            switch (mState)
            {
            case State.DecData:
            {
                mBuf[mBufPos] = input;
                if (++mBufPos == mBuf.Length)
                {
                    mPoly1305.BlockUpdate(mBuf, 0, BufSize);
                    ProcessData(mBuf, 0, BufSize, outBytes, outOff);
                    mBuf.CopyTo(mBuf, BufSize, 0, MacSize);
                    this.mBufPos = MacSize;
                    return BufSize;
                }

                return 0;
            }
            case State.EncData:
            {
                mBuf[mBufPos] = input;
                if (++mBufPos == BufSize)
                {
                    ProcessData(mBuf, 0, BufSize, outBytes, outOff);
                    mPoly1305.BlockUpdate(outBytes, outOff, BufSize);
                    this.mBufPos = 0;
                    return BufSize;
                }

                return 0;
            }
            default:
                throw new InvalidOperationException();
            }
        }

        public virtual int ProcessBytes(ByteArray inBytes, int inOff, int len, ByteArray outBytes, int outOff)
        {
            if (null == inBytes)
                throw new ArgumentNullException("inBytes");
            if (null == outBytes)
                throw new ArgumentNullException("outBytes");
            if (inOff < 0)
                throw new ArgumentException("cannot be negative", "inOff");
            if (len < 0)
                throw new ArgumentException("cannot be negative", "len");
            if (inBytes.Length < len)
                throw new DataLengthException("input buffer too short");

            if (outOff < 0)
                throw new ArgumentException("cannot be negative", "outOff");

            CheckData();

            int resultLen = 0;

            switch (mState)
            {
            case State.DecData:
            {
                for (int i = 0; i < len; ++i)
                {
                    mBuf[mBufPos] = inBytes[inOff + i];
                    if (++mBufPos == mBuf.Length)
                    {
                        mPoly1305.BlockUpdate(mBuf, 0, BufSize);
                        ProcessData(mBuf, 0, BufSize, outBytes, outOff + resultLen);
                        mBuf.CopyTo(mBuf, BufSize, 0, MacSize);
                        this.mBufPos = MacSize;
                        resultLen += BufSize;
                    }
                }
                break;
            }
            case State.EncData:
            {
                if (mBufPos != 0)
                {
                    while (len > 0)
                    {
                        --len;
                        mBuf[mBufPos] = inBytes[inOff++];
                        if (++mBufPos == BufSize)
                        {
                            ProcessData(mBuf, 0, BufSize, outBytes, outOff);
                            mPoly1305.BlockUpdate(outBytes, outOff, BufSize);
                            this.mBufPos = 0;
                            resultLen = BufSize;
                            break;
                        }
                    }
                }

                while (len >= BufSize)
                {
                    ProcessData(inBytes, inOff, BufSize, outBytes, outOff + resultLen);
                    mPoly1305.BlockUpdate(outBytes, outOff + resultLen, BufSize);
                    inOff += BufSize;
                    len -= BufSize;
                    resultLen += BufSize;
                }

                if (len > 0)
                {
                    inBytes.CopyTo(mBuf, inOff, 0, len);
                    this.mBufPos = len;
                }
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            return resultLen;
        }

        public virtual int DoFinal(ByteArray outBytes, int outOff)
        {
            if (null == outBytes)
                throw new ArgumentNullException("outBytes");
            if (outOff < 0)
                throw new ArgumentException("cannot be negative", "outOff");

            CheckData();

            mMac.Clear(0, MacSize);

            int resultLen = 0;

            switch (mState)
            {
            case State.DecData:
            {
                if (mBufPos < MacSize)
                    throw new InvalidCipherTextException("data too short");

                resultLen = mBufPos - MacSize;

                if(outBytes.Length - outOff < resultLen)
                    throw new OutputLengthException("output buffer too short");

                if (resultLen > 0)
                {
                    mPoly1305.BlockUpdate(mBuf, 0, resultLen);
                    ProcessData(mBuf, 0, resultLen, outBytes, outOff);
                }

                FinishData(State.DecFinal);


                if (!Arrays.ConstantTimeAreEqual(MacSize, mMac.Bytes, mMac.Offset, mBuf.Bytes, mBuf.Offset+ resultLen))
                {
                    throw new InvalidCipherTextException("mac check in ChaCha20Poly1305 failed");
                }

                break;
            }
            case State.EncData:
            {
                resultLen = mBufPos + MacSize;

                if(outBytes.Length - outOff < resultLen) {
                    throw new OutputLengthException("output buffer too short");
                }

                if (mBufPos > 0)
                {
                    ProcessData(mBuf, 0, mBufPos, outBytes, outOff);
                    mPoly1305.BlockUpdate(outBytes, outOff, mBufPos);
                }

                FinishData(State.EncFinal);

                mMac.CopyTo(outBytes, 0, outOff + mBufPos, MacSize);
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            Reset(false, true);

            return resultLen;
        }

        public virtual byte[] GetMac() {
            return mMac.ToExactByteArrayCopy();
        }

        public virtual void Reset()
        {
            Reset(true, true);
        }

        private void CheckAad()
        {
            switch (mState)
            {
            case State.DecInit:
                this.mState = State.DecAad;
                break;
            case State.EncInit:
                this.mState = State.EncAad;
                break;
            case State.DecAad:
            case State.EncAad:
                break;
            case State.EncFinal:
                throw new InvalidOperationException("ChaCha20Poly1305 cannot be reused for encryption");
            default:
                throw new InvalidOperationException();
            }
        }

        private void CheckData()
        {
            switch (mState)
            {
            case State.DecInit:
            case State.DecAad:
                FinishAad(State.DecData);
                break;
            case State.EncInit:
            case State.EncAad:
                FinishAad(State.EncData);
                break;
            case State.DecData:
            case State.EncData:
                break;
            case State.EncFinal:
                throw new InvalidOperationException("ChaCha20Poly1305 cannot be reused for encryption");
            default:
                throw new InvalidOperationException();
            }
        }

        private void FinishAad(State nextState)
        {
            PadMac(mAadCount);

            this.mState = nextState;
        }

        private void FinishData(State nextState)
        {
            PadMac(mDataCount);

            ByteArray lengths = ByteArray.Create(16);
            Pack.UInt64_To_LE(mAadCount, lengths.Bytes, lengths.Offset);
            Pack.UInt64_To_LE(mDataCount, lengths.Bytes, lengths.Offset+ 8);
            mPoly1305.BlockUpdate(lengths, 0, 16);

            mPoly1305.DoFinal(mMac, 0);

            this.mState = nextState;
        }

        private ulong IncrementCount(ulong count, uint increment, ulong limit)
        {
            if (count > (limit - increment))
                throw new InvalidOperationException ("Limit exceeded");

            return count + increment;
        }

        private void InitMac() {
            
            try
            {
                ByteArray firstBlock = ByteArray.Create(64);
                mChacha20.ProcessBytes(firstBlock, 0, 64, firstBlock, 0);
                mPoly1305.Init(new KeyParameter2(firstBlock, 0, 32));
            }
            finally
            {
            }
        }

        private void PadMac(ulong count)
        {
            int partial = (int)count % MacSize;
            if (0 != partial)
            {
                mPoly1305.BlockUpdate(Zeroes, 0, MacSize - partial);
            }
        }

        private void ProcessData(ByteArray inBytes, int inOff, int inLen, ByteArray outBytes, int outOff)
        {
            Check.OutputLength(outBytes.Bytes, outBytes.Offset+ outOff, inLen, "output buffer too short");

            mChacha20.ProcessBytes(inBytes, inOff, inLen, outBytes, outOff);

            this.mDataCount = IncrementCount(mDataCount, (uint)inLen, DataLimit);
        }

        private void Reset(bool clearMac, bool resetCipher)
        {
            mBuf.Clear();

            if (clearMac)
            {
                mMac.Clear();
            }

            this.mAadCount = 0UL;
            this.mDataCount = 0UL;
            this.mBufPos = 0;

            switch (mState)
            {
            case State.DecInit:
            case State.EncInit:
                break;
            case State.DecAad:
            case State.DecData:
            case State.DecFinal:
                this.mState = State.DecInit;
                break;
            case State.EncAad:
            case State.EncData:
            case State.EncFinal:
                this.mState = State.EncFinal;
                return;
            default:
                throw new InvalidOperationException();
            }

            if (resetCipher)
            {
                mChacha20.Reset();
            }

            InitMac();

            if (null != mInitialAad)
            {
                ProcessAadBytes(mInitialAad, 0, mInitialAad.Length);
            }
        }
    }
}
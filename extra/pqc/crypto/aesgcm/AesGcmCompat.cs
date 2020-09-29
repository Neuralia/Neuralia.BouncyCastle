using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Neuralia.BouncyCastle.extra.pqc.crypto.aesgcm
{
    public sealed class AesGcmCompat : IDisposable
    {
        private const int NonceSizeInBytes = 12;
        private static KeySizes KeyByteSizes { get; } = new KeySizes(16, 32, 8);
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSizeInBytes, NonceSizeInBytes, 1);
        public static KeySizes TagByteSizes { get; } = new KeySizes(12, 16, 1);

        private readonly byte[] _key;
        public AesGcmCompat(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            CheckKeySize(key.Length);

            _key = key;
        }

        public AesGcmCompat(ReadOnlySpan<byte> key)
        {
            CheckKeySize(key.Length);

            _key = key.ToArray();
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);

            Decrypt((ReadOnlySpan<byte>)nonce, ciphertext, tag, plaintext, associatedData);
        }

        public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default(ReadOnlySpan<byte>))
        {
            CheckParameters(nonce, plaintext, ciphertext, tag);

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters =
                      new AeadParameters(new KeyParameter(_key), tag.Length * 8, nonce.ToArray(), associatedData == default ? null : associatedData.ToArray());
            
            cipher.Init(false, parameters);

            byte[] plainBytes = new byte[cipher.GetOutputSize(ciphertext.Length + tag.Length)];
            int retLen = 0;
            for (int i = 0; i < ciphertext.Length; i++)
            {
                int offset = (i + 1) - (cipher.GetBlockSize() + tag.Length);
                retLen += cipher.ProcessByte(ciphertext[i], plainBytes, offset);
            }
            for (int i = 0; i < tag.Length; i++)
            {
                int offset = ciphertext.Length + (i + 1) - (cipher.GetBlockSize() + tag.Length);
                retLen += cipher.ProcessByte(tag[i], plainBytes, offset);
            }

            cipher.DoFinal(plainBytes, retLen);

            plainBytes.CopyTo(plaintext);
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = null)
        {
            CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);

            Encrypt((ReadOnlySpan<byte>)nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData = default(ReadOnlySpan<byte>))
        {
            CheckParameters(nonce, plaintext, ciphertext, tag);

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters =
                         new AeadParameters(new KeyParameter(_key), tag.Length * 8, nonce.ToArray(), associatedData == default ? null : associatedData.ToArray());

            cipher.Init(true, parameters);

            byte[] encryptedBytes = new byte[cipher.GetOutputSize(plaintext.Length)];
            int retLen = 0;
            for (int i = 0; i < plaintext.Length; i++)
            {
                int offset = (i + 1) - cipher.GetBlockSize();
                retLen += cipher.ProcessByte(plaintext[i], encryptedBytes, offset);
            }

            cipher.DoFinal(encryptedBytes, retLen);

            cipher.GetMac().CopyTo(tag);

            ReadOnlySpan<byte> encryptedBytesWithoutMac = encryptedBytes.AsSpan().Slice(0, encryptedBytes.Length - tag.Length);
            encryptedBytesWithoutMac.CopyTo(ciphertext);
        }

        #region Private helpers
        private void CheckKeySize(int keySizeInBytes)
        {
            if (!isLegalSize(keySizeInBytes, KeyByteSizes))
            {
                throw new CryptographicException($"The received key size is {keySizeInBytes * 8} bits. It should be of 128 bits, 192 bits or 256 bits.");
            }
        }

        private void CheckArgumentsForNull(
            byte[] nonce,
            byte[] plaintext,
            byte[] ciphertext,
            byte[] tag)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (tag == null)
                throw new ArgumentNullException(nameof(tag));
        }

        private void CheckParameters(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag)
        {
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException($"Length of {nameof(ciphertext)} should be of equal size to {nameof(plaintext)}.", nameof(ciphertext));

            if (!isLegalSize(nonce.Length, NonceByteSizes))
                throw new ArgumentException($"Length of {nameof(nonce)} should be equal to one of the valid sizes allowed by {nameof(NonceByteSizes)}", nameof(nonce));

            if (!isLegalSize(tag.Length, TagByteSizes))
                throw new ArgumentException($"Length of {nameof(tag)} should be equal to one of the valid sizes allowed by {nameof(TagByteSizes)}", nameof(tag));
        }

        private bool isLegalSize(int size, KeySizes legalSizes)
        {
            for (int i = legalSizes.MinSize; i <= legalSizes.MaxSize; i = i + legalSizes.SkipSize)
            {
                if (size == i)
                    return true;
            }

            return false;
        }
        #endregion

        #region IDisposable Support
        bool isDisposed = false;
        private void dispose(bool disposing)
        {
            if (!isDisposed)
            {
                if (disposing)
                {
                    //Anything to dispose?
                }

                isDisposed = true;
            }
        }

        ~AesGcmCompat()
        {
            dispose(false);
        }

        public void Dispose()
        {
            dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}

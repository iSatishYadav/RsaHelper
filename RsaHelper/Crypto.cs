using System;
using System.Security.Cryptography;
using System.Text;

namespace RsaHelper
{
    public static class Crypto
    {
        public static string Encrypt(this string plainText, string publicKey, int keysize)
        {
            #region Housekeeping
            if (plainText == null)
                throw new ArgumentNullException(nameof(plainText));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            #endregion
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            using (var rsa = new RSACryptoServiceProvider(keysize))
            {
                rsa.FromXmlString(publicKey);
                var encryptedBytes = rsa.Encrypt(plainBytes, true);
                var encryptedString = Convert.ToBase64String(encryptedBytes);
                return encryptedString;
            }

        }
        public static string Decrypt(this string cipher, string privateKey, int keySize)
        {
            if (cipher == null)
                throw new ArgumentNullException(nameof(cipher));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            var cipherBytes = Convert.FromBase64String(cipher);
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                rsa.FromXmlString(privateKey);

                var plainBytes = rsa.Decrypt(cipherBytes, true);
                var plainText = Encoding.UTF8.GetString(plainBytes);
                return plainText;
            }
        }
    }
}



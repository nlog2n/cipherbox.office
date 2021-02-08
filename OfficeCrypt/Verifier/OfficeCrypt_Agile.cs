using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

using CipherBox.Office.Common;
using CipherBox.Cryptography.Net;
using CipherBox.Cryptography.Utility;

namespace CipherBox.Office.Agile
{
    public class AgileEncryptionHeader : IVerifier
	{
		#region Class variables

		public ushort			versionMajor		= 4;  // MUST
		public ushort			versionMinor		= 4;  // MUST
        public EncryptionFlags  encryptionFlags     = EncryptionFlags.fAgile;

        // XmlEncryptionDescriptor: keyData, dataIntegrity, keyEncryptors
        
        // keyData
        public int    kdSaltSize                 = 0x10;  // Default value, in bytes
        public int    kdBlockSize                = 0x10;  // in bytes
        public int    kdKeyBits                  = 256; // keySize in bits,  AES = 0x00000080, 0x000000C0, 0x00000100  for 128, 192 or 256-bit 
        public int    kdHashSize                 = 64;  // verifierHashSize, in bytes
        public string kdCipherAlgorithm          = CipherAlgorithms.AES; 
        public string kdCipherChaining           = ChainingModes.CBC;
        public string kdHashAlgorithm            = HashAlgorithms.SHA512; 
        public byte[] kdSaltValue                = null;  // saltValue, from base64string

        // dataIntegrity
        public byte[] encryptedHmacKey           = null;
        public byte[] encryptedHmacValue         = null;

        // keyEncryptors
        public int    pkeSpinCount               = 100000; // 
        public int    pkeSaltSize                = 0x10;
        public int    pkeBlockSize               = 0x10;
        public int    pkeKeyBits                 = 256;
        public int    pkeHashSize                = 64;
        public string pkeCipherAlgorithm         = CipherAlgorithms.AES; 
        public string pkeCipherChaining          = ChainingModes.CBC;
        public string pkeHashAlgorithm           = HashAlgorithms.SHA512; 
        public byte[] pkeSaltValue               = null;  // saltValue, from base64string
        public byte[] pkeEncryptedVerifierHashInput = null; // from base64string
        public byte[] pkeEncryptedVerifierHashValue = null; // from base64string
        public byte[] pkeEncryptedKeyValue       = null; // from base64string


        // for content, optional
		public byte[]			encryptedPackage		= null;  

		#endregion

        // sec. 2.4.13
        public bool VerifyPassword(string password)
        {
            HashAlgorithm hashAlg = GetHashAlgorithm();
            if (hashAlg == null) return false;

            SymmetricAlgorithm cipher = GetCipherAlgorithm();
            if (cipher == null) return false;

            var verifierHashInput_cipherKey = GenerateEncryptionKey(password, BlockKey.EncryptedVerifierHashInput);
            var decryptedVerifierHashInputBytes = SymmetricCipher.Decrypt(cipher,
                verifierHashInput_cipherKey,
                this.pkeSaltValue, 
                this.pkeEncryptedVerifierHashInput);

            var hash = hashAlg.ComputeHash(decryptedVerifierHashInputBytes);

            var verifierHashValue_cipherKey = GenerateEncryptionKey(password, BlockKey.EncryptedVerifierHashValue);
            var decryptedVerifierHashBytes = SymmetricCipher.Decrypt(cipher,
                verifierHashValue_cipherKey, 
                this.pkeSaltValue,
                this.pkeEncryptedVerifierHashValue);

            bool passwordVerificationMatch = decryptedVerifierHashBytes.Take(this.pkeHashSize).Select((b, i) => hashAlg.ComputeHash(decryptedVerifierHashInputBytes)[i] == b).All(b => b);
            if (!passwordVerificationMatch)
            {
                //Console.WriteLine("Password incorrect"); // failure
                return false;
            }

            //Console.WriteLine("Password succeed");
            return true;
        }


        // more check the data integrity of encryptedPackage (2.3.4.14), rather than just password verification
        public bool VerifyDataIntegrity(byte[] decryptedKeyValue, byte[] encryptedPackage)
        {
            HashAlgorithm hashAlg = GetHashAlgorithm();
            if (hashAlg == null) return false;

            SymmetricAlgorithm cipher = GetCipherAlgorithm();
            if (cipher == null) return false;

            // Decrypt the salt value
            byte[] ivDataIntegritySalt = GenerateIV(hashAlg, this.kdSaltValue, BlockKey.EncryptedDataIntegritySalt, this.kdBlockSize);
            var decryptedDataIntegritySaltValue = SymmetricCipher.Decrypt(cipher, 
                decryptedKeyValue,    // as cipher key
                ivDataIntegritySalt,  // as IV
                this.encryptedHmacKey);

            // further use the salt to hash the encrypted document
            KeyedHashAlgorithm keyDataHashAlg = KeyedHashAlgorithm.Create("HMAC" + this.kdHashAlgorithm);  // note: Net2.0 only supports HMACSHA1 and MACTripleDES, while NET3.5 for all
            keyDataHashAlg.Key = decryptedDataIntegritySaltValue.Take(this.kdHashSize).ToArray();
            var dataIntegrityHash = keyDataHashAlg.ComputeHash(encryptedPackage);


            // Decrypt the hash generated by the encryptor
            byte[] ivDataIntegrityHash = GenerateIV(hashAlg, this.kdSaltValue, BlockKey.EncryptedDataIntegrityHmacValue, this.kdBlockSize);
            var decryptedDataIntegrityHmacValue = SymmetricCipher.Decrypt(cipher, 
                decryptedKeyValue,    // as cipher key
                ivDataIntegrityHash,  // as IV
                this.encryptedHmacValue);

            // dataIntegrityHash should equal the decryptedDataIntegrityHmacValue
            bool dataIntegrityMatch = decryptedDataIntegrityHmacValue.Take(this.kdHashSize).Select((b, i) => dataIntegrityHash[i] == b).All(b => b);
            if (!dataIntegrityMatch)
            {
                Console.WriteLine("Encrypted package is invalid");
                return false;
            }

            return true;
        }




        // generate encryption key for data integrity check and decryption 
        // See the last paragraph of section (2.3.4.13)
        public byte[] GenerateEncryptionKey(string password)
        {
            SymmetricAlgorithm cipher = GetCipherAlgorithm();
            if (cipher == null) return null;

            var key = GenerateEncryptionKey(password, BlockKey.EncryptedKeyValue);

            return SymmetricCipher.Decrypt(cipher, 
                key, // as cipher Key
                this.pkeSaltValue,  // as IV
                this.pkeEncryptedKeyValue);
        }


        #region Generic hash function

        // Hash(buf || block), where block could be unsigned int iterator value or block key
        public static byte[] Hash(HashAlgorithm alg, byte[] hashBuf, byte[] block)
        {
            return alg.ComputeHash(ByteArrayUtils.Concat(hashBuf, block));
        }

        #endregion


        // section 2.3.4.11 generate agile encryption key
        public byte[] GenerateEncryptionKey(string password, byte[] blockKey)
        {
            HashAlgorithm hashAlg = GetHashAlgorithm();
            if (hashAlg == null) return null;

            // H(0) = H(salt, password);
            // Use a unicode form of the password
            byte[] passwordBuf = System.Text.UnicodeEncoding.Unicode.GetBytes(password);
            var hashBuf = Hash(hashAlg, this.pkeSaltValue, passwordBuf);

            for (int i = 0; i < this.pkeSpinCount; i++)
            {
                // H(n) = H(i, H(n-1))
                hashBuf = Hash(hashAlg, System.BitConverter.GetBytes(i), hashBuf);
            }

            // Finally, append "block" (0) to H(n)
            hashBuf = Hash(hashAlg, hashBuf, blockKey);

            // Fix up the size per the spec 2.3.4.11
            return ByteArrayUtils.Tailor(hashBuf, this.pkeKeyBits >> 3, 0x36);
        }


        // Create an IV. The technique is documented here 2.3.4.10.
        // note: data encryption uses 0x36 padding, while data integrity check uses 0x00 padding
        public static byte[] GenerateIV(HashAlgorithm hashAlg, byte[] keySalt, byte[] blockKey, int blockSize)
        {
            byte[] iv = null; 
            if (blockKey != null)
            {
                iv = Hash(hashAlg, keySalt, blockKey);
            }
            else
            {
                iv = new byte[keySalt.Length];
                Array.Copy(keySalt, iv, keySalt.Length);
            }

            return ByteArrayUtils.Tailor(iv, blockSize, 0x36); //padding = 0x36;
        }



        #region Create the hash and symmetric algorithm

        public HashAlgorithm GetHashAlgorithm()
        {
            return HashGenerator.GetHashAlgorithm(this.pkeHashAlgorithm);
        }

        public SymmetricAlgorithm GetCipherAlgorithm()
        {
            SymmetricAlgorithm cipher = SymmetricCipher.GetCipherAlgorithm(this.pkeCipherAlgorithm);
            if (cipher == null)
                return null;
            
            switch (this.pkeCipherChaining)
            {
                case ChainingModes.CFB:
                    cipher.Mode = CipherMode.CFB;
                    break;

                case ChainingModes.CBC:
                default:
                    cipher.Mode = CipherMode.CBC;
                    break;
            }

            cipher.BlockSize = this.pkeBlockSize << 3;  // bits
            cipher.KeySize = this.pkeKeyBits;
            cipher.Padding = PaddingMode.Zeros;

            return cipher;
        }

        #endregion




        public string ToDisplayString()
        {
            string result = "\nEncryption type: Agile 2010";
            result += "\nVersion:" + versionMajor.ToString() + "." + versionMinor.ToString();
            result += "\nFlag:" + encryptionFlags.ToString();
            
            // keyData
            result += "\n\n<KeyData>";
            result += "\nkdCipherAlgorithm:" + kdCipherAlgorithm + "," + kdCipherChaining;
            result += "\nkdKeyBits:" + kdKeyBits.ToString();
            result += "\nkdHashAlgorithm:" + kdHashAlgorithm;
            result += "\nkdHashSize:" + kdHashSize.ToString();
            result += "\nkdSaltSize:" + kdSaltSize.ToString();
            result += "\nkdSaltValue:" + BitConverter.ToString(kdSaltValue); // saltValue, from base64string
            result += "\nkdBlockSize:" + kdBlockSize.ToString();

            // dataIntegrity
            result += "\n\n<DataIntegrity>";
            result += "\nencryptedHmacKey:" + BitConverter.ToString(encryptedHmacKey);
            result += "\nencryptedHmacValue:" + BitConverter.ToString(encryptedHmacValue);
            
            // keyEncryptors
            result += "\n\n<KeyEncryptors>";
            result += "\npkeCipherAlgorithm:" + pkeCipherAlgorithm + "," + pkeCipherChaining;
            result += "\npkeKeyBits:" + pkeKeyBits.ToString();
            result += "\npkeHashAlgorithm:" + pkeHashAlgorithm;
            result += "\npkeHashSize:" + pkeHashSize.ToString();
            result += "\npkeSaltSize:" + pkeSaltSize.ToString();
            result += "\npkeSaltValue:" + BitConverter.ToString(pkeSaltValue); // saltValue, from base64string
            result += "\npkeBlockSize:" + pkeBlockSize.ToString();
            result += "\npkeSpinCount:" + pkeSpinCount.ToString();
            result += "\npkeEncryptedVerifierHashInput:" + BitConverter.ToString(pkeEncryptedVerifierHashInput); // from base64string
            result += "\npkeEncryptedVerifierHashValue:" + BitConverter.ToString(pkeEncryptedVerifierHashValue); // from base64string
            result += "\npkeEncryptedKeyValue:" + BitConverter.ToString(pkeEncryptedKeyValue); // from base64string

            return result;
        }

	}
}

/*
 * legacy RC4 for office97/2000: RC4 + MD5, see section 2.3.6
 * provide password verification functions:
 *    VerifyPassword
 *  
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Cryptography.Net;
using CipherBox.Cryptography;

namespace CipherBox.Office.Legacy
{
    public class RC4EncryptionHeader:IVerifier
    {
        public int blockSize = 512;   // in bytes, 512 for word and 1024 for excel

        //====================================================== FibBase from worddocument
        public FibBaseEncryptionFlags encryptionFlags; // specify encryption flags like obfuscation or rc4
        public int IKey = 0x34; // it is length of encryption header if rc4


        //====================================================== Encryption header from 1Table/0Table
        public ushort versionMajor = 1;
        public ushort versionMinor = 1;
        //public uint keySize = 128; // RC4 key in bits, fixed. NOT 40 bits actually
        public uint   saltSize              = 0x10;  // fixed
        public byte[] salt                  = null;
        public byte[] encryptedVerifier     = null;
        public uint   verifierHashSize      = 0x10;  // in bytes
        public byte[] encryptedVerifierHash = null;


        //====================================================== encrypted data, optional
        public byte[] table = null;
        public byte[] wordDocument = null;
        public byte[] data = null;
        public byte[] tablePlain = null;
        public byte[] wordDocumentPlain = null;
        public byte[] dataPlain = null;
        public byte[] contents = null;


        // derive the encryption key from the salt and the password
        public byte[] GenerateEncryptionKey(string password, uint block)
        {
            MDFive md5 = new MDFive(); // MD5 md5 = MD5.Create();

            // First, derive the encryption key from the salt and the password
            byte[] pwdBuf = System.Text.UnicodeEncoding.Unicode.GetBytes(password);
            byte[] pwdHash = md5.ComputeHash(pwdBuf); // md5.ComputeHash(pwdBuf);

            // Now create the hashing buffer with the hash of the password and the salt. 
            // Cryptographically, this is not a good approach, but that's how it was done.
            byte[] hashBuf = new byte[21 * 16];
            for (int i = 0; i < 16; i++)
            {
                Array.Copy(pwdHash, 0, hashBuf, i * 21, 5);
                Array.Copy(this.salt, 0, hashBuf, i * 21 + 5, 16);
            }

            // Get the hash of the previous buffer
            pwdHash = md5.ComputeHash(hashBuf);

            // Now factor in the block number
            Array.Copy(pwdHash, 0, hashBuf, 0, 5);
            Array.Copy(BitConverter.GetBytes(block), 0, hashBuf, 5, 4);

            pwdHash = md5.ComputeHash(hashBuf, 0, 9);
            md5.Clear();

            // The RC4 key is actually always 128-bit, not 40 bits. see 2.3.6.2
            byte[] rc4Key = new byte[16];
            Array.Copy(pwdHash, rc4Key, 16);
            return rc4Key;
        }


        public bool VerifyPassword(string password)
        {
            // First, derive the encryption key from the salt and the password
            byte[] rc4Key = GenerateEncryptionKey(password, 0);

            // Now use the ManagedRC4 to decrypt the two encrypted elements of the verifier
            RC4 rc4 = new RC4(rc4Key);
            byte[] verifier = rc4.Decrypt(this.encryptedVerifier);
            byte[] verifierHash = rc4.Decrypt(this.encryptedVerifierHash);

            // Finally, hash the decrypted verifier, and compare
            MDFive md5 = new MDFive(); // MD5.Create();
            byte[] hashedVerifier = md5.ComputeHash(verifier);
            for (int i = 0; i < hashedVerifier.Length; i++)
            {
                if (hashedVerifier[i] != verifierHash[i])
                {
                    return false;  // no match
                }
            }
            md5.Clear();
            return true;
        }


        public string ToDisplayString()
        {
            string result = "\nEncryption type: RC4";

            result += "\nVersion:" + versionMajor.ToString() + "." + versionMinor.ToString();
            //result += "\nAlgID:" + algId.ToString();
            //result += "\nAlgHashID:" + algHashId.ToString();
            //result += "\nKeySize:" + keySize.ToString();
            //result += "\nProviderType:" + providerType.ToString();
            //result += "\nCSPName:" + CSPName;
            //result += "\nSaltSize:" + saltSize.ToString();
            result += "\nFibBaseFlags:" + encryptionFlags.ToString();
            result += "\nIKey:" + IKey.ToString();
            result += "\nSalt:" + BitConverter.ToString(salt, 0, (int)saltSize);
            result += "\nEncryptedVerifier:" + BitConverter.ToString(encryptedVerifier, 0, 16);
            result += "\nEncryptedVerifierHash:" + BitConverter.ToString(encryptedVerifierHash, 0, (int)verifierHashSize);
            return result;
        }

    }
        
}

// Capi RC4 for office2002/2003: RC4 + SHA-1

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

using CipherBox.Office.OLE;
using CipherBox.Cryptography.Net;
using CipherBox.Cryptography;
using CipherBox.Office.Common;

namespace CipherBox.Office.CryptoAPI
{
    public class RC4EncryptionCryptoAPIHeader : IVerifier
    {
        //=================================================from 1Table/0Table

        public ushort          versionMajor          = 2; // must be 2, 3, or 4
        public ushort          versionMinor          = 2; // must be 2
        public EncryptionFlags encryptionFlags       = EncryptionFlags.fCryptoAPI;

        // headerSize

        // Encryption header 
        public uint            sizeExtra             = 0;
        public AlgId           algId                 = AlgId.RC4;
        public AlgHashId       algHashId             = AlgHashId.SHA1;
        public uint            keySize               = 0; // in bits,  must >= 0x28, <= 0x80, in increment of 8 bits.
        public ProviderType    providerType          = ProviderType.RC4;
        public string          CSPName               = ProvName.MS_DEF_PROV; 

        // Encryption verifier
        public uint            saltSize              = 0x10;  // fixed
        public byte[]          salt                  = null;
        public byte[]          encryptedVerifier     = null;
        public uint            verifierHashSize      = 0x14;  // in bytes
        public byte[]          encryptedVerifierHash = null;

        //=================================================end


        public bool VerifyPassword(string password)
        {
            SHAOne sha1 = new SHAOne(); 

            // First, derive the encryption key from the salt and the password
            byte[] pwdBuf = System.Text.UnicodeEncoding.Unicode.GetBytes(password);
            byte[] initialHashInput = new byte[16 + pwdBuf.Length];
            Array.Copy(this.salt, 0, initialHashInput, 0, 16); // Copy the salt
            Array.Copy(pwdBuf, 0, initialHashInput, 16, pwdBuf.Length); // Copy the password

            // H0 = H(salt + password)
            byte[] hLast = sha1.ComputeHash(initialHashInput);

            // Hfinal = H(H0 + block)
            byte[] hashInput = new byte[hLast.Length + 4];
            uint block = 0;
            Array.Copy(hLast, hashInput, hLast.Length);
            Array.Copy(BitConverter.GetBytes(block), 0, hashInput, hLast.Length, 4);
            hLast = sha1.ComputeHash(hashInput);

            // derive the key for rc4
            // when specified key size = 40, office will pad zeroes to extend to 128 bit
            byte[] rc4Key;
            if (this.keySize == 40)
            {
                rc4Key = new byte[16]; // c# will set default byte value 0
            }
            else
            {
                rc4Key = new byte[this.keySize / 8];
            }
            Array.Copy(hLast, rc4Key, this.keySize / 8);


            // Now use the ManagedRC4 implementation to decrypt the two encrypted elements of the verifier
            RC4 rc4 = new RC4(rc4Key);
            byte[] verifier = rc4.Decrypt(this.encryptedVerifier);
            byte[] verifierHash = rc4.Decrypt(this.encryptedVerifierHash);

            // Finally, hash the decrypted verifier, and compare
            byte[] hashedVerifier = sha1.ComputeHash(verifier);
            for (int i = 0; i < hashedVerifier.Length; i++)
            {
                if (hashedVerifier[i] != verifierHash[i])
                {
                    return false; // no match
                }
            }

            sha1.Clear();
            return true;
        }




        public string ToDisplayString()
        {
            string result = "\nEncryption type: RC4 CryptoAPI";

            result += "\nVersion:" + versionMajor.ToString() + "." + versionMinor.ToString();
            result += "\nFlag:" + encryptionFlags.ToString();
            result += "\nAlgID:" + algId.ToString();
            result += "\nAlgHashID:" + algHashId.ToString();
            result += "\nKeySize:" + keySize.ToString() +"bits";
            result += "\nProviderType:" + providerType.ToString();
            result += "\nCSPName:" + CSPName;
            result += "\nSaltSize:" + saltSize.ToString();
            result += "\nSalt:" + BitConverter.ToString(salt, 0, (int)saltSize);
            result += "\nEncryptedVerifier:" + BitConverter.ToString(encryptedVerifier, 0, 16);
            result += "\nEncryptedVerifierHash:" + BitConverter.ToString(encryptedVerifierHash, 0, 20); // (int)verifierHashSize);

            return result;
        }

    }

}

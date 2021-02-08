/*
 * XOR obfuscation for office97/2000: 
 * note: only doc and xls support obfuscation
 *  
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

using CipherBox.Office.OLE;
using CipherBox.Office.Common;

namespace CipherBox.Office.Obfuscation
{
    public class XorObfuscationHeader : IVerifier
    {
        //====================================================== FibBase from worddocument
        public FibBaseEncryptionFlags encryptionFlags; // specify encryption flags like obfuscation or rc4
        public int IKey = 0x34; // it is length of encryption header if rc4


        //====================================================== Encryption header from 1Table/0Table
        public ushort versionMajor = 1;
        public ushort versionMinor = 1;
        public uint   saltSize              = 0x10;  // fixed
        public byte[] salt                  = null;
        public byte[] encryptedVerifier     = null;
        public uint   verifierHashSize      = 0x10;  // in bytes
        public byte[] encryptedVerifierHash = null;


        //====================================================== encrypted data, optional
        public byte[] contents = null;


        public bool VerifyPassword(string password)
        {
            return false;
        }


        public string ToDisplayString()
        {
            string result = "\nEncryption type: XOR obfuscation";

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

    public static class XorObfuscation
    {
        public static bool VerifyPassword(XorObfuscationHeader info, string password)
        {
            return false;
        }
    }
}

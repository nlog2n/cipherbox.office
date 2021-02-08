/*
 * 
 *  Decrypytion and verification core library for Office 2007 Open XML files
 *  for Office 2007, decrypt or encrypt stream together with encryptInfo into a file
 * 
 * Modified by Fang Hui 20121207
 * - works with NPOI (for OLE Compound File access)
 * - added a few methods for convenience (e.g. EncryptToFile, EncryptToStream)
 */

using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

using CipherBox.Office.Common;
using CipherBox.Cryptography.Net;
using CipherBox.Cryptography.Utility;
using CipherBox.Cryptography;
using CipherBox.Office.Utility;


namespace CipherBox.Office.Standard
{
    public static class StandardEncryption 
	{
        #region The core of package decryption

        internal static byte[] DecryptInternal(string password, byte[] encryptionInfo, byte[] encryptedPackage)
        {
            // parse the encryption info
            StandardEncryptionHeader docInfo = ParseEncryptionInfoFromBytes(encryptionInfo);
            if (docInfo == null) return null;

            // verify password and generate key
            byte[] encryptionKey = null;
            if (!docInfo.VerifyPassword(password, out encryptionKey)) return null;

            // now decrypt "encryptedPackage" by generated "encryptionKey"

            // First 8 bytes hold the actual size of the stream
            long length = BitConverter.ToInt64(encryptedPackage, 0);
            var encryptedChunk = ByteArrayUtils.Skip(encryptedPackage, 8);  // encryptedPackage.Skip(8).ToArray();

            // Decrypt the stream using the generated and validated key
            byte[] decryptedBytes = AESCipherEcbNoPad.Decrypt(encryptedChunk, encryptionKey);

            // there will be zero-padding since ECB mode is used
            // !! IMPORTANT !! Make sure the final array is the correct size
            // Failure to do this will cause an error when the decrypted stream
            // is opened by the System.IO.Packaging.Package.Open() method.
            byte[] result = decryptedBytes;
            if (decryptedBytes.Length > length)
            {
                result = new byte[length];
                Array.Copy(decryptedBytes, result, result.Length);
            }

            return result;
        }

        #endregion



        #region The core of package encryption


        /// <summary>
        /// Encrypts a package (zip) file using a supplied password and returns 
        /// an array to create an encryption information stream and a byte array 
        /// of the encrypted package.
        /// </summary>
        /// <param name="packageContents">The package (zip) file to be encrypted</param>
        /// <param name="password">The password to decrypt the package</param>
        /// <param name="encryptionInfo">An array of bytes containing the encrption info</param>
        /// <param name="encryptedPackage">The encrpyted package</param>
        /// <returns></returns>
        public static void EncryptPackage(byte[] packageContents, string password, out byte[] encryptionInfo, out byte[] encryptedPackage)
        {
            // create a sample encryptionInfo bytes for writing to file, default is AES128 and SHA1
            byte[] key;
            StandardEncryptionHeader doc;
            CreateEncryptionInfo(password, out key, out doc);
            encryptionInfo = CreateEncryptionInfo(doc);

            // now encrypt on package contents
            int originalLength = packageContents.Length;

            // Pad the array to the nearest 16 byte boundary
            int remainder = packageContents.Length % 0x10;
            if (remainder != 0)
            {
                byte[] tempContents = new byte[packageContents.Length + 0x10 - remainder];
                Array.Copy(packageContents, tempContents, packageContents.Length);
                packageContents = tempContents;
            }

            byte[] encryptionResult = AESCipherEcbNoPad.Encrypt(packageContents, key);

            // Need to prepend the original package size as a Int64 (8 byte) field
            encryptedPackage = new byte[encryptionResult.Length + 8];
            // MUST record the original length here
            Array.Copy(BitConverter.GetBytes((long)originalLength), encryptedPackage, 8);
            Array.Copy(encryptionResult, 0, encryptedPackage, 8, encryptionResult.Length);
        }
        
        #endregion


        #region parse encryption info

        // parse encryptionInfo stream from bytes in office 2007 format
        // normally for 2007 v3.2, v4.2 offset = 0x0e40h, and length = 0xA4 or 0x8C
        public static StandardEncryptionHeader ParseEncryptionInfoFromBytes(byte[] encryptionInfo)
        {
            if (encryptionInfo == null) return null;

            try
            {
                using (System.IO.MemoryStream ms = new System.IO.MemoryStream(encryptionInfo))
                {
                    System.IO.BinaryReader reader = new System.IO.BinaryReader(ms);

                    StandardEncryptionHeader doc = new StandardEncryptionHeader();

                    // version
                    doc.versionMajor = reader.ReadUInt16();
                    doc.versionMinor = reader.ReadUInt16();
                    if (!(doc.versionMajor == 3 || doc.versionMajor == 4) || doc.versionMinor != 2)  // for ECMA-376 format only
                    {
                        //Console.WriteLine("warning: incorrect version " + doc.versionMajor.ToString() + "." + doc.versionMinor.ToString());
                        return null;
                    }

                    // flags
                    doc.encryptionFlags = (EncryptionFlags)reader.ReadUInt32();
                    if (doc.encryptionFlags == EncryptionFlags.fExternal)
                    {
                        Console.WriteLine("an external cryptographic provider is not supported");
                        return null;
                    }
                    if (doc.encryptionFlags != (EncryptionFlags)(EncryptionFlags.fAES | EncryptionFlags.fCryptoAPI)) // 0x24
                    {
                        Console.WriteLine("incorrect flags");
                        return null;
                    }

                    // encryption header length, includes: flags again, size extra, alg ID, alg hash ID, key size AES, provider type, and CSP name
                    uint headerLength = reader.ReadUInt32();

                    // flags again
                    int skipFlags = reader.ReadInt32(); headerLength -= 4;
                    if (doc.encryptionFlags != (EncryptionFlags)skipFlags)
                    {
                        Console.WriteLine("warning encryptionHeader flags mismatch");
                        return null;
                    }

                    // SizeExtra has to be 0
                    doc.sizeExtra = reader.ReadUInt32(); headerLength -= 4;
                    if (doc.sizeExtra != 0)
                    {
                        Console.WriteLine("warning encryptionHeader sizeExtra incorrect");
                        return null;
                    }


                    // algID
                    doc.algId = (AlgId)reader.ReadUInt32(); headerLength -= 4;
                    switch (doc.algId)
                    {
                        case AlgId.AES128: // AES128, 0x0000660E
                        case AlgId.AES192: // AES192, 0x0000660F
                        case AlgId.AES256: // AES256, 0x00006610
                            break;
                        default:
                            Console.WriteLine("encryptionHeader AlgID incorrect");
                            return null;
                    }


                    // AlgIdHash - must be SHA1
                    doc.algHashId = (AlgHashId)reader.ReadUInt32(); headerLength -= 4;
                    if (doc.algHashId != AlgHashId.SHA1) //  0x00008004
                    {
                        Console.WriteLine("encryptionHeader AlgIDHash incorrect");
                        return null;
                    }


                    // Encryption key size
                    doc.keySize = reader.ReadUInt32(); headerLength -= 4;
                    switch (doc.keySize)
                    {
                        case 0x80:
                            if (doc.algId != AlgId.AES128)
                            {
                                Console.WriteLine("mismatched algID and key size");
                                return null;
                            }
                            break;
                        case 0xC0:
                            if (doc.algId != AlgId.AES192)
                            {
                                Console.WriteLine("mismatched algID and key size");
                                return null;
                            }
                            break;
                        case 0x10:
                            if (doc.algId != AlgId.AES256)
                            {
                                Console.WriteLine("mismatched algID and key size");
                                return null;
                            }
                            break;
                        default:
                            Console.WriteLine("EncryptionHeader.KeySize incorrect");
                            return null;
                    }

                    doc.providerType = (ProviderType)reader.ReadUInt32(); headerLength -= 4;
                    reader.ReadUInt32(); headerLength -= 4; // Reserved 1
                    reader.ReadUInt32(); headerLength -= 4; // Reserved 2
                    doc.CSPName = System.Text.UnicodeEncoding.Unicode.GetString(reader.ReadBytes((int)headerLength));

                    // Encryption verifier, includes: saltSize(4Bytes), salt(16B), encryptedVerifier(16B), verifierHashSize(4B), and encryptedVerifierHash(32B)
                    // check the size of encryption verifier ??
                    doc.saltSize = reader.ReadUInt32();
                    if (doc.saltSize != 0x10)
                    {
                        Console.WriteLine("saltSize invalid");
                        return doc;
                    }

                    doc.salt = reader.ReadBytes((int)doc.saltSize);

                    doc.encryptedVerifier = reader.ReadBytes(0x10);

                    doc.verifierHashSize = reader.ReadUInt32();
                    if (doc.verifierHashSize != 0x14) // sha1 only takes 20 bytes
                    {
                        Console.WriteLine("VerifierHashSize invalid");
                        return null;
                    }

                    doc.encryptedVerifierHash = reader.ReadBytes(doc.providerType == ProviderType.RC4 ? 0x14 : 0x20);

                    return doc;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }

        #endregion



        #region  Create encryption info header

        private static byte[] CreateEncryptionInfo(StandardEncryptionHeader doc)
        {
            // Generate the encryption header structure
            byte[] encryptionHeader = null;
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {
                System.IO.BinaryWriter br = new System.IO.BinaryWriter(ms);
                br.Write((int)doc.encryptionFlags);
                br.Write((int)doc.sizeExtra);
                br.Write((int)doc.algId);
                br.Write((int)doc.algHashId);
                br.Write((int)doc.keySize);
                br.Write((int)doc.providerType);
                br.Write(new byte[] { 0xA0, 0xC7, 0xDC, 0x02, 0x00, 0x00, 0x00, 0x00 }); // reserved
                br.Write(System.Text.UnicodeEncoding.Unicode.GetBytes(doc.CSPName));

                ms.Flush();
                encryptionHeader = ms.ToArray();
            }

            // Generate the encryption verifier structure
            byte[] encryptionVerifier = null;
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {
                System.IO.BinaryWriter br = new System.IO.BinaryWriter(ms);
                br.Write((int)doc.salt.Length);
                br.Write(doc.salt);
                br.Write(doc.encryptedVerifier);
                br.Write(doc.verifierHashSize); // Hash length
                br.Write(doc.encryptedVerifierHash);

                ms.Flush();
                encryptionVerifier = ms.ToArray();
            }

            // Now generate the encryption info structure
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {
                System.IO.BinaryWriter br = new System.IO.BinaryWriter(ms);
                br.Write(doc.versionMajor);
                br.Write(doc.versionMinor);
                br.Write((int)doc.encryptionFlags);
                br.Write((int)encryptionHeader.Length);
                br.Write(encryptionHeader);
                br.Write(encryptionVerifier);

                ms.Flush();
                byte[] encryptionInfo = ms.ToArray();
                return encryptionInfo;
            }
        }

        // create a sample encryptionInfo bytes for writing to file, default is AES128 and SHA1
        private static void CreateEncryptionInfo(string password, out byte[] key, out StandardEncryptionHeader doc)
        {
            doc = new StandardEncryptionHeader(); // note some default values already set inside
            doc.versionMajor = 3; // sometimes I also get v4.2 which is OK 
            doc.versionMinor = 2;

            // 1) Generate a random salt
            doc.saltSize = 0x10;
            doc.salt = IVGenerator.RandomIV((int)doc.saltSize); 
            doc.verifierHashSize = 0x14; // SHA1 size (uint)tempSalt.Length;

            // 2) Generate a key from salt and password
            key = doc.GeneratePasswordKey(password); // need salt

            // Generate EncryptionVerifier, 2.3.3

            // 3) Generate 16 bytes of additional random data as the Verifier, and encrypted
            byte[] verifier = IVGenerator.RandomIV(16);  // verifier and salt must be different!
            doc.encryptedVerifier = AESCipherEcbNoPad.Encrypt(verifier, key);


            // 4)	For the hashing algorithm chosen, obtain the size of the hash data and write this value 
            //		into the VerifierHashSize field.
            // Not applicable right now

            // 5)	Obtain the hashing algorithm output using an input of data generated in step 3. 
            SHAOne sha1 = new SHAOne();
            byte[] verifierHash = sha1.ComputeHash(verifier);
            sha1.Clear();


            // 6)	Encrypt the hashing algorithm output from step 5 using the encryption algorithm 
            //		chosen, and write the output into the EncryptedVerifierHash field.
            byte[] tempHash = new byte[0x20]; // First pad to 32 bytes
            Array.Copy(verifierHash, tempHash, verifierHash.Length);
            verifierHash = tempHash;
            doc.encryptedVerifierHash = AESCipherEcbNoPad.Encrypt(verifierHash, key);
        }


        #endregion


	}
}

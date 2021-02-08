using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Office.CryptoAPI;
using CipherBox.Office.Legacy;

namespace CipherBox.Office.Word
{
    public static class WordParser
    {
        // for "doc" file
        // return: IVerifier, either RC4EncryptionHeader or RC4EncryptionCryptoAPIHeader

        // header is at the start of the 1Table stream, usually 0x1400 or 0x2400 offset
        public static RC4EncryptionCryptoAPIHeader ReadWordHeader_capi(string filename)
        {
            try
            {
                var storage = new OleStorage(filename);

                byte[] oneTable = storage.ReadStream(StreamNames.cs1TableStreamName);
                if (oneTable == null) return null;

                return RC4EncryptionCryptoAPI.ParseRC4CryptoAPIEncryptionHeader(oneTable);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }


        // input: file contents
        public static RC4EncryptionCryptoAPIHeader ReadWordHeader_capi(byte[] packageContents)
        {
            try
            {
                // create an OLE object
                var storage = new OleStorage(packageContents);

                byte[] oneTable = storage.ReadStream(StreamNames.cs1TableStreamName);
                if (oneTable == null) return null;

                return RC4EncryptionCryptoAPI.ParseRC4CryptoAPIEncryptionHeader(oneTable);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }


        // input: file contents
        public static RC4EncryptionHeader ReadWordHeader_legacy(byte[] packageContents)
        {
            try
            {
                var storage = new OleStorage(packageContents);

                return ReadWordHeader_legacy(storage);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }


        // input: file OLE storage
        public static RC4EncryptionHeader ReadWordHeader_legacy(IStorageWrapper storage)
        {
            try
            {
                RC4EncryptionHeader docInfo = new RC4EncryptionHeader();

                // Begin reading the File Information Block (FIB) at offset 0 of the Word Document stream
                docInfo.wordDocument = storage.ReadStream(StreamNames.csWordDocumentStreamName);
                if (docInfo.wordDocument == null) return null;

                docInfo.IKey = BitConverter.ToInt32(docInfo.wordDocument, 14);

                // Read the 1-bit FibBase.fEncrypted flag at byte 11 of the FIB.
                // If fEncrypted = 0, the file is not encrypted, and you may exit this procedure.
                // If fEncrypted = 1, read the FibBase.fObfuscated flag at the last bit of byte 11.
                //    If fObfuscated = 1, the file uses XOR obfuscation, which does not affect the arrangement of OLE objects.
                //    If fObfuscated = 0, read the first 2 bytes of the table stream as an unsigned integer 
                //    which specifies the encryption major version. If this number is larger than 0x0001, 
                //    the file uses Office Binary Document RC4 CryptoAPI Encryption.
                docInfo.encryptionFlags = (FibBaseEncryptionFlags)docInfo.wordDocument[11];
                if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fEncrypted) == 0) return null; // no encryption
                if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fObfuscated) != 0) return null; // XOR obfuscation not supported yet
                if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fExtChar) == 0) return null; // format incorrect

                if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fWhichTblStm) == 0)
                {
                    docInfo.table = storage.ReadStream(StreamNames.cs0TableStreamName);
                }
                else
                {
                    docInfo.table = storage.ReadStream(StreamNames.cs1TableStreamName);
                }
                if (docInfo.table == null) return null;

                docInfo.data = null; // Data stream may not exist
                if (storage.FoundStream(StreamNames.csDataStreamName))
                {
                    docInfo.data = storage.ReadStream(StreamNames.csDataStreamName);
                }

                RC4EncryptionHeader infoext = RC4Encryption.ParseRC4EncryptionHeader(docInfo.table);
                {
                    docInfo.versionMajor = infoext.versionMajor;
                    docInfo.versionMinor = infoext.versionMinor;
                    docInfo.salt = infoext.salt;
                    docInfo.encryptedVerifier = infoext.encryptedVerifier;
                    docInfo.encryptedVerifierHash = infoext.encryptedVerifierHash;
                }
                return docInfo;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }




    }
}
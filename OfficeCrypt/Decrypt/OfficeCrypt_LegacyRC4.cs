/*
 * legacy RC4 for office97/2000: RC4 + MD5, see section 2.3.6
 * provide password verification and IO functions:
 *    ReadHeader
 *    VerifyPassword
 *  
 */


// file extension + OLEFileHeader => Office 97-2003 Compound File Binary
// further check "WordDocument.FIB.FibBase" to see if it is encrypted
// if so, get verifier info from "1Table" stream



using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Cryptography;
using CipherBox.Cryptography.Net;


namespace CipherBox.Office.Legacy
{
    public static class RC4Encryption
    {
        // parse 1Table stream
        public static RC4EncryptionHeader ParseRC4EncryptionHeader(byte[] encryptionInfo)
        {
            if (encryptionInfo == null) return null;

            try
            {
                using (System.IO.MemoryStream ms = new System.IO.MemoryStream(encryptionInfo))
                {
                    System.IO.BinaryReader reader = new System.IO.BinaryReader(ms);

                    RC4EncryptionHeader info = new RC4EncryptionHeader();

                    // version
                    info.versionMajor = reader.ReadUInt16();
                    info.versionMinor = reader.ReadUInt16();
                    if (!(info.versionMajor == 1 && info.versionMinor == 1))
                    {
                        return null;  // wrong version
                    }

                    // Fixed size verifier, includes: salt(16 bytes), encryptedVerifier(16B), encryptedVerifierHash(16B)
                    info.salt = reader.ReadBytes(16);
                    info.encryptedVerifier = reader.ReadBytes(16);
                    info.encryptedVerifierHash = reader.ReadBytes(16);

                    return info;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }


        public static void EncryptToFile( byte[] plaincontents, string password, string encryptedFilename )
        {
            // read input file content as OLE object
            // note: this is a kinda redundant because previously we already read OLE file in...
            var storage = new OleStorage(plaincontents); 

            // create an example encryption header
            RC4EncryptionHeader docInfo = new RC4EncryptionHeader();
            docInfo.salt = IVGenerator.RandomIV(16);     // random salt
            byte[] verifier = IVGenerator.RandomIV(16);  // random verifier, not saved
            byte[] rc4Key = docInfo.GenerateEncryptionKey(password, 0); // need salt
            RC4 rc4 = new RC4(rc4Key);
            docInfo.encryptedVerifier = rc4.Encrypt(verifier);
            MDFive md5 = new MDFive(); // MD5.Create();
            byte[] hashedVerifier = md5.ComputeHash(verifier);
            md5.Clear();
            docInfo.encryptedVerifierHash = rc4.Encrypt(hashedVerifier);

            // get plain streams and encrypt
            byte[] wordDocument = storage.ReadStream(StreamNames.csWordDocumentStreamName);
            if (wordDocument == null) return;
            wordDocument[11] = (byte)(((FibBaseEncryptionFlags)wordDocument[11]) | FibBaseEncryptionFlags.fEncrypted);
            wordDocument[14] = 0x34;  // IKey
            docInfo.encryptionFlags = (FibBaseEncryptionFlags)wordDocument[11];
            docInfo.IKey = wordDocument[14];

            byte[] table = null;
            if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fWhichTblStm) != 0)
            {
                table = storage.ReadStream(StreamNames.cs1TableStreamName);
            }
            else
            {
                table = storage.ReadStream(StreamNames.cs0TableStreamName);
            }
            if (table == null) return;


            byte[] data = null;
            if (storage.FoundStream(StreamNames.csDataStreamName))
            {
                data = storage.ReadStream(StreamNames.csDataStreamName);
            }

            // encrypt 1Table stream
            byte[] rawTable = EncryptByBlock(docInfo, password, table);
            // add one encryption header
            byte[] eTable = new byte[0x34 + rawTable.Length];
            eTable[0] = 0x01; // version
            eTable[2] = 0x01;
            Array.Copy(docInfo.salt, 0, eTable, 4, 16);
            Array.Copy(docInfo.encryptedVerifier, 0, eTable, 4 + 16, 16);
            Array.Copy(docInfo.encryptedVerifierHash, 0, eTable, 4 + 16 + 16, 16);
            Array.Copy(rawTable, 0, eTable, 4 + 16 + 16 + 16, rawTable.Length);


            // encrypt wordDocument stream
            byte[] eWordDocument = EncryptByBlock(docInfo, password, wordDocument);
            // write first 68 bytes in plain
            Array.Copy(wordDocument, 0, eWordDocument, 0, 68);

            // encrypt data stream
            byte[] eData = null;
            if (data != null)
            {
                eData = EncryptByBlock(docInfo, password, data);
            }

            // TODO: bugs here!!
            // rewrite those streams, including: WordDocument, 1Table, and Data
            // other streams include: CompObj, SummaryInformation, DocumentSummaryInformation etc
            var estorage = new OleStorage();
            foreach (string s in storage.ListStreams())
            {
                if (s != StreamNames.csWordDocumentStreamName
                    && s != StreamNames.csDataStreamName
                    && s != StreamNames.cs1TableStreamName)
                {
                    estorage.WriteStream(s, storage.ReadStream(s));
                }
            }

            estorage.WriteStream(StreamNames.csWordDocumentStreamName, eWordDocument);
            if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fWhichTblStm) != 0)
            {
                estorage.WriteStream(StreamNames.cs1TableStreamName, eTable);
            }
            else
            {
                estorage.WriteStream(StreamNames.cs0TableStreamName, eTable);
            }
            if (eData != null)
            {
                estorage.WriteStream(StreamNames.csDataStreamName, eData);
            }

            // save to file
            //estorage.SaveAs( "enc_" + encryptedFilename);
        }



        public static bool Decrypt(RC4EncryptionHeader docInfo, string password)
        {
            if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fEncrypted) == 0) return false; // no encryption
            if ((docInfo.encryptionFlags & FibBaseEncryptionFlags.fObfuscated) != 0) return false; // XOR obfuscation not supported yet

            // verify firstly
            if (!docInfo.VerifyPassword(password)) return false;

            // decrypt 1Table stream
            byte[] raw = DecryptByBlock(docInfo, password, docInfo.table);
            byte[] plainTable = new byte[raw.Length - docInfo.IKey];  // remove encryption header
            Array.Copy(raw, docInfo.IKey, plainTable, 0, plainTable.Length);
            Console.WriteLine("\nPlain 1Table:" + BitConverter.ToString(plainTable, 0, 128) + "...(" + plainTable.Length.ToString() + ")");

            // decrypt WordDocument stream
            byte[] prefix68 = new byte[68];
            Array.Copy(docInfo.wordDocument, 0, prefix68, 0, prefix68.Length);
            prefix68[11] = 0x12;  // flag reset
            prefix68[14] = 0; // IKey = 0
            byte[] plainDocument = DecryptByBlock(docInfo, password, docInfo.wordDocument);
            Array.Copy(prefix68, 0, plainDocument, 0, prefix68.Length);  // write first 68 bytes in plaintxt
            Console.WriteLine("\nPlain WordDocument:" + BitConverter.ToString(plainDocument,0,128)  + "...(" + plainDocument.Length.ToString() + ")");

            // decrypt Data stream
            byte[] plainData = null;
            if (docInfo.data != null)
            {
                plainData = DecryptByBlock(docInfo, password, docInfo.data);
                Console.WriteLine("\nPlain Data:" + BitConverter.ToString(plainData, 0, 64) + "...(" + plainData.Length.ToString() + ")");
            }

            // save
            docInfo.tablePlain = plainTable;
            docInfo.wordDocumentPlain = plainDocument;
            docInfo.dataPlain = plainData;

            return true;
        }

        private static byte[] DecryptByBlock(RC4EncryptionHeader info, string password, byte[] encryptedData)
        {
            byte[] plainData = new byte[encryptedData.Length];
            for (uint i = 0; i < encryptedData.Length; i += (uint)info.blockSize)
            {
                uint blockNum = (uint)(i / info.blockSize);
                byte[] rc4Key = info.GenerateEncryptionKey(password, blockNum); // need salt and block size
                RC4 rc4 = new RC4(rc4Key);

                int len = (int)(encryptedData.Length - i); 
                len = (len < info.blockSize ? len : info.blockSize);
                byte[] encblock = new byte[len];
                Array.Copy(encryptedData, i, encblock, 0, encblock.Length);

                byte[] plainblock = rc4.Decrypt(encblock);

                Array.Copy(plainblock, 0, plainData, i, plainblock.Length);
            }

            return plainData;
        }


        private static byte[] EncryptByBlock(RC4EncryptionHeader info, string password, byte[] plainData)
        {
            byte[] encryptedData = new byte[plainData.Length];
            for (uint i = 0; i < plainData.Length; i += (uint)info.blockSize)
            {
                uint blockNum = (uint)(i / info.blockSize);
                byte[] rc4Key = info.GenerateEncryptionKey(password, blockNum); // need salt and block size
                RC4 rc4 = new RC4(rc4Key);

                int len = (int)(plainData.Length - i);
                len = (len < info.blockSize ? len : info.blockSize);
                byte[] plainblock = new byte[len];
                Array.Copy(plainData, i, plainblock, 0, plainblock.Length);

                byte[] encblock = rc4.Encrypt(plainblock);

                Array.Copy(encblock, 0, encryptedData, i, encblock.Length);
            }

            return encryptedData;
        }





    }
}

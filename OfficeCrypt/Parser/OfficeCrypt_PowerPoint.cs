using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Office.CryptoAPI;



namespace CipherBox.Office.PowerPoint
{
    public static class PowerPointParser
    {
        // for "ppt" file, which only supports RC4EncryptionCryptoAPIHeader
        public static RC4EncryptionCryptoAPIHeader ReadPPTHeader(byte[] packageContents)
        {
            // create an OLE object
            var storage = new OleStorage(packageContents);

            byte[] encryptedSummary = storage.ReadStream(StreamNames.csEncryptedSummary);
            if (encryptedSummary == null) return null; // no encryption

            byte[] pptDocument = storage.ReadStream(StreamNames.csPowerPointDocument);
            if (pptDocument == null) return null; // format error

            // RC4 CryptoAPI is default for powerpoint
            byte[] encryptionHeader = pptGetEncryptionHeaderBytes(pptDocument);
            if (encryptionHeader == null) return null; // format error

            return RC4EncryptionCryptoAPI.ParseRC4CryptoAPIEncryptionHeader(encryptionHeader);
        }

        // ppt only supports RC4 CryptoAPI, which encryption header is at the end of PowerPoint Document stream
        private static byte[] pptGetEncryptionHeaderBytes(byte[] PowerPointDocumentStream)
        {
            byte[] result = null;
            byte[] stream = PowerPointDocumentStream;
            for (int i = stream.Length - 1; i >= 3; i--)
            {
                // pinpoint the "CryptSession10Container" record in "PowerPoint Document" stream
                // record header = { recVer =0x0F, recInstance=0x00, recType= 0x2F14, recLen= 0x000000BE(example) }
                // record data   = following encryptionHeader. 
                // recLen specifies the length of data
                if (stream[i - 3] == 0x0F && stream[i - 2] == 0x00 && stream[i - 1] == 0x14 && stream[i] == 0x2F)
                {
                    // read rh.recLen
                    int recLen = BitConverter.ToInt32(stream, i + 1);

                    result = new byte[recLen];
                    Array.Copy(stream, i + 1 + 4, result, 0, recLen);

                    break;
                }
            }

            return result;
        }





    }
}
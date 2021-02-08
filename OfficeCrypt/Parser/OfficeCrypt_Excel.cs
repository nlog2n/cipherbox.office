using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Office.Legacy;
using CipherBox.Office.CryptoAPI;

namespace CipherBox.Office.Excel
{
    public static class ExcelParser
    {
        // for "xls" file
        // return: either RC4EncryptionHeader or RC4EncryptionCryptoAPIHeader
        public static IVerifier ReadExcelHeader(byte[] packageContents)
        {
            try
            {
                var storage = new OleStorage(packageContents);

                return ReadExcelHeader(storage);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }


        // for "xls" file
        // return: either RC4EncryptionHeader or RC4EncryptionCryptoAPIHeader
        public static IVerifier ReadExcelHeader(IStorageWrapper storage)
        {
            try
            {
                // pick up tyhe "Workbook" stream
                byte[] xlsWorkbook = storage.ReadStream(StreamNames.csWorkbookStreamName);
                if (xlsWorkbook == null) return null;

                // the first substeam should be "Globals". if it contains a record named "FilePass", then it is encrypted
                //  Workbook head --> Globals = { BOF, WriteProtect, FilePass...}
                // the "FilePass" record shoulbe be the first or second record.

                int lenBOF = 16;
                int offsetFilePass = 4 + lenBOF;  // not sure what are first 4 bytes for
                int recType = BitConverter.ToInt16(xlsWorkbook, offsetFilePass);
                int recLen = BitConverter.ToInt16(xlsWorkbook, offsetFilePass + 2);
                byte[] recData = new byte[recLen];
                Array.Copy(xlsWorkbook, offsetFilePass + 2 + 2, recData, 0, recData.Length);
                if (recType == 0x2F)  // 47: FilePass record type
                {
                    // encrypted, fall thru
                }
                else if (recType == 0x86) // 134: WriteProtect record type
                {
                    offsetFilePass += 2 + 2 + recLen;
                    recType = BitConverter.ToInt16(xlsWorkbook, offsetFilePass);
                    recLen = BitConverter.ToInt16(xlsWorkbook, offsetFilePass + 2);
                    recData = new byte[recLen];
                    Array.Copy(xlsWorkbook, offsetFilePass + 2 + 2, recData, 0, recData.Length);
                    if (recType == 0x2F)  // secord record is for FilePass
                    {
                        // encrypted, fall thru
                    }
                    else
                    {
                        return null; // not encrypted
                    }
                }
                else
                {
                    return null; // not encrypted
                }

                // now we got FilePass record: recData = {encryptionType, encryptionInfo}
                int encryptionType = BitConverter.ToInt16(recData, 0);
                if (encryptionType != 0x0001)
                {
                    // xor obfuscation for 0x0000,  or format error
                    Console.WriteLine("are u using XOR obfuscation? it is not safe.");
                    return null;  // TODO: not yet supported
                }

                byte[] encryptionHeader = new byte[recData.Length - 2];
                Array.Copy(recData, 2, encryptionHeader, 0, encryptionHeader.Length);

                // RC4 encryption: either legacy or cryptoAPI
                // determined by version number
                int verMajor = BitConverter.ToInt16(recData, 2);
                if (verMajor == 0x0001)
                {
                    // legacy RC4
                    return RC4Encryption.ParseRC4EncryptionHeader(encryptionHeader);
                }
                else
                {
                    // cryptoAPI RC4
                    return RC4EncryptionCryptoAPI.ParseRC4CryptoAPIEncryptionHeader(encryptionHeader);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }






    }
}
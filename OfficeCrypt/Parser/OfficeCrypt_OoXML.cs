using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices;


using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Office.Standard;
using CipherBox.Office.Agile;
using CipherBox.Office.Utility;

// handle office files for standard and agile encryption, which have something in common:
//   plain file  == Zip format
//   encrypted file == OLE format with 2 streams (encryptionInfo, encryptedPackage)

namespace CipherBox.Office.OoXML
{
    // read encryptionInfo and encryptedPackage from office header
    public static class OoXMLParser
    {
        #region decryption wrapper

        public static MemoryStream DecryptToStream(string filename, string password, ProtectionFlag pFlag)
        {
            return PackageExtension.CreateStream(DecryptToBytes(filename, password, pFlag));
        }

        public static MemoryStream DecryptToStream(byte[] contents, string password, ProtectionFlag pFlag)
        {
            return PackageExtension.CreateStream(DecryptToBytes(contents, password, pFlag));
        }


        public static byte[] DecryptToBytes(string filename, string password, ProtectionFlag pFlag)
        {
            return DecryptToBytes(new OleStorage(filename), password, pFlag);
        }


        public static byte[] DecryptToBytes(byte[] contents, string password, ProtectionFlag pFlag)
        {
            return DecryptToBytes(new OleStorage(contents), password, pFlag); 
        }



        /// <summary>
        /// Validates and opens the storage containing the encrypted package.
        /// Reads the encryption information and encrypted package
        /// Parses the encryption information
        /// Generates a decrypytion key and validates it against the password
        /// Decrypts the encrypted package.
        /// </summary>
        /// <param name="filename">OLE storage object containing the encrypted package</param>
        /// <param name="password">The password to decrypt the package</param>
        /// <returns>Decrypted package in bytes</returns>
        private static byte[] DecryptToBytes(IStorageWrapper storage, string password, ProtectionFlag pFlag)
        {
            // read streams
            // The file must contain a stream called EncryptionInfo for valid Office 2007/2010 encrypted document
            byte[] encryptionInfo = storage.ReadStream(StreamNames.csEncryptionInfoStreamName);
            if (encryptionInfo == null) return null;

            // The file must contain a stream called EncryptedPackage for valid Office 2007/2010 encrypted document
            byte[] encryptedPackage = storage.ReadStream(StreamNames.csEncryptedPackageStreamName);
            if (encryptedPackage == null) return null;

            // decrypt
            if (pFlag == ProtectionFlag.Standard)
            {
                return StandardEncryption.DecryptInternal(password, encryptionInfo, encryptedPackage);
            }
            else if (pFlag == ProtectionFlag.Agile)
            {
                return AgileEncryption.DecryptInternal(password, encryptionInfo, encryptedPackage);
            }
            else
            {
                return null;
            }
        }
        #endregion


        #region encryption wrapper
        /// <summary>
        /// Encrypts a package (zip) file using a supplied password and returns 
        /// an array to create an encryption information stream and a byte array 
        /// of the encrypted package.
        /// </summary>
        /// <param name="filename">The package (zip) file to be encrypted</param>
        /// <param name="password">The password to decrypt the package</param>
        /// <param name="encryptionInfo">An array of bytes containing the encrption info</param>
        /// <param name="encryptedPackage">The encrpyted package</param>
        /// <returns></returns>
        public static bool EncryptToFile(string filename, string password, string encryptedFilename, ProtectionFlag pFlag)
        {
            // Grab the package contents and encrypt
            try
            {
                byte[] packageContents = FileUtils.ReadAllBytes(filename);
                if (packageContents == null)
                {
                    return false;
                }

                EncryptToFile(packageContents, password, encryptedFilename, pFlag);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }


        public static void EncryptToFile(byte[] packageContents, string password, string encryptedFilename, ProtectionFlag pFlag)
        {
            byte[] bytes = EncryptToBytes(packageContents, password, pFlag); 
            if (bytes != null)
            {
                FileUtils.WriteAllBytes(encryptedFilename, bytes);
            }
            else
            {
                Console.WriteLine("warning: null storage stream, not saved.");
            }
        }

        public static void EncryptToStream(byte[] packageContents, string password, Stream outEncryptedStream, ProtectionFlag pFlag)
        {
            byte[] bytes = EncryptToBytes(packageContents, password, pFlag);
            if (bytes != null)
            {
                outEncryptedStream.Write(bytes, 0, bytes.Length);
            }
            else
            {
                Console.WriteLine("warning: null storage stream, not saved.");
            }
        }


        /// <summary>
        /// Encrypt the bytes of plain content, using the given password. 
        /// </summary>
        /// <param name="packageContents">Plaintext contents of the package.</param>
        /// <param name="password">Password to use to encrypt.</param>
        /// <param name="encryptedFilename">Name of the encrypted stream write to</param>
        public static byte[] EncryptToBytes(byte[] packageContents, string password, ProtectionFlag pFlag)
        {
            // encrypt streams
            byte[] encryptionInfo;
            byte[] encryptedPackage;
            if (pFlag == ProtectionFlag.Standard)
            {
                StandardEncryption.EncryptPackage(packageContents, password, out encryptionInfo, out encryptedPackage);
            }
            else if (pFlag == ProtectionFlag.Agile)
            {
                AgileEncryption.EncryptPackage(packageContents, password, out encryptionInfo, out encryptedPackage);
            }
            else
            {
                return null;
            }

            // write to a storage object
            var storage = new OleStorage();

            // write DataSpaces streams, OPTIONAL. refer to: excel2file EncryptedPackageHandler.cs
            CreateDataSpaces(storage);

            storage.WriteStream(StreamNames.csEncryptionInfoStreamName, encryptionInfo);
            storage.WriteStream(StreamNames.csEncryptedPackageStreamName, encryptedPackage);

            // get bytes from storage
            byte[] bytes = storage.GetAllBytes();
            return bytes;
        }

        #endregion


        #region "Dataspaces Stream methods"

/* Example:
DataSpaces: storage
        Version, 76 bytes
        DataSpaceMap, 112 bytes
        DataSpaceInfo: storage
                StrongEncryptionDataSpace, 64 bytes
        TransformInfo: storage
                StrongEncryptionTransform: storage
                        Primary, 208 bytes
EncryptionInfo, 248 bytes
EncryptedPackage, 11416 bytes
*/
        private static void CreateDataSpaces(OleStorage storage)
        {
            // DataSpaces storage
            IStorage dataSpaces = storage.CreateStorage("\x06" + "DataSpaces");

            // DataSpaces\Version stream
            byte[] version = CreateVersionStream();
            storage.WriteStream(dataSpaces, "Version", version);

            // DataSpaces\DataSpaceMap stream
            byte[] dataSpaceMap = CreateDataSpaceMap();
            storage.WriteStream(dataSpaces, "DataSpaceMap", dataSpaceMap);

            // DataSpaces\DataSpaceInfo storage
            IStorage dataSpaceInfo = storage.CreateStorage(dataSpaces, "DataSpaceInfo");

            // DataSpaces\DataSpaceInfo\StrongEncryptionDataSpace stream
            byte[] strongEncryptionDataSpace = CreateStrongEncryptionDataSpaceStream();
            storage.WriteStream(dataSpaceInfo, "StrongEncryptionDataSpace", strongEncryptionDataSpace);

            // DataSpaces\TransformInfo storage
            IStorage tranformInfo = storage.CreateStorage(dataSpaces, "TransformInfo");

            // DataSpaces\TransformInfo\StrongEncryptionTransform storage
            IStorage strongEncryptionTransform = storage.CreateStorage(tranformInfo, "StrongEncryptionTransform");

            // DataSpaces\TransformInfo\StrongEncryptionTransform\x06Primary stream
            byte[] primary = CreateTransformInfoPrimary();
            storage.WriteStream(strongEncryptionTransform, "\x06Primary", primary);

            // release those temp IStorage objects
            Marshal.ReleaseComObject(strongEncryptionTransform);
            Marshal.ReleaseComObject(tranformInfo);
            Marshal.ReleaseComObject(dataSpaceInfo);
            Marshal.ReleaseComObject(dataSpaces);
        }

        private static byte[] CreateStrongEncryptionDataSpaceStream()
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);

            bw.Write((int)8);       //HeaderLength
            bw.Write((int)1);       //EntryCount

            string tr = "StrongEncryptionTransform";
            bw.Write((int)tr.Length);
            bw.Write(UTF8Encoding.Unicode.GetBytes(tr + "\0")); // end \0 is for padding

            bw.Flush();
            return ms.ToArray();
        }
        private static byte[] CreateVersionStream()
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);

            bw.Write((short)0x3C);  //Major
            bw.Write((short)0);     //Minor
            bw.Write(UTF8Encoding.Unicode.GetBytes("Microsoft.Container.DataSpaces"));
            bw.Write((int)1);       //ReaderVersion
            bw.Write((int)1);       //UpdaterVersion
            bw.Write((int)1);       //WriterVersion

            bw.Flush();
            return ms.ToArray();
        }
        private static byte[] CreateDataSpaceMap()
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);

            bw.Write((int)8);       //HeaderLength
            bw.Write((int)1);       //EntryCount
            string s1 = "EncryptedPackage";
            string s2 = "StrongEncryptionDataSpace";
            bw.Write((int)s1.Length + s2.Length + 0x14);
            bw.Write((int)1);       //ReferenceComponentCount
            bw.Write((int)0);       //Stream=0
            bw.Write((int)s1.Length * 2); //Length s1
            bw.Write(UTF8Encoding.Unicode.GetBytes(s1));
            bw.Write((int)(s2.Length - 1) * 2);   //Length s2
            bw.Write(UTF8Encoding.Unicode.GetBytes(s2 + "\0"));   // end \0 is for padding

            bw.Flush();
            return ms.ToArray();
        }
        private static byte[] CreateTransformInfoPrimary()
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);
            string TransformID = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}";
            string TransformName = "Microsoft.Container.EncryptionTransform";
            bw.Write(TransformID.Length * 2 + 12);
            bw.Write((int)1);
            bw.Write(TransformID.Length * 2);
            bw.Write(UTF8Encoding.Unicode.GetBytes(TransformID));
            bw.Write(TransformName.Length * 2);
            bw.Write(UTF8Encoding.Unicode.GetBytes(TransformName + "\0"));
            bw.Write((int)1);   //ReaderVersion
            bw.Write((int)1);   //UpdaterVersion
            bw.Write((int)1);   //WriterVersion

            // Note: this works for XLSX, XLSB, PPTX and DOCX. 
            // but DOCX 2007 sometimes is slightly different for a few last bytes, which does not matter actually.
            bw.Write((int)0);
            bw.Write((int)0);
            bw.Write((int)0);       //CipherMode
            bw.Write((int)4);       //Reserved

            bw.Flush();
            return ms.ToArray();
        }
        #endregion




    }
}
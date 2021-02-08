/******************************************************************************* 
 * 
 *  Decrypytion library for Office Open XML files (using Agile Encryption)
 * 
 * Algorithms in this code file are based on the MS-OFFCRYPT.PDF provided by
 * Microsoft as part of its Open Specification Promise (OSP) program and which 
 * is available here:
 * 
 * http://msdn.microsoft.com/en-us/library/cc313071.aspx
 * 
 */

// agile encryption for office 2010
// public interface: OoXmlAgileCrypto.DecryptToArray( filename, password )

// original filename: OoXmlAgileCrypto3.cs

using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;

using CipherBox.Office.Common;
using CipherBox.Office.Utility;
using CipherBox.Cryptography;
using CipherBox.Cryptography.Net;

namespace CipherBox.Office.Agile
{
    public class XmlTokenNames
    {
        public const string XmlRootUri = "http://schemas.microsoft.com/office/2006/encryption";
        public const string XmlRootUriPKE = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";

        public const string keyData = "keyData";
        public const string dataIntegrity = "dataIntegrity";
        public const string keyEncryptors = "keyEncryptors";

        public const string keyEncryptor = "keyEncryptor";

        public const string encryption = "encryption";
        public const string encryptedKey = "encryptedKey";

        public const string blockSize = "blockSize";
        public const string keyBits = "keyBits";
        public const string hashSize = "hashSize";
        public const string saltSize = "saltSize";
        public const string saltValue = "saltValue";
        public const string cipherAlgorithm = "cipherAlgorithm";
        public const string cipherChaining = "cipherChaining";
        public const string hashAlgorithm = "hashAlgorithm";
        public const string encryptedHmacKey = "encryptedHmacKey";
        public const string encryptedHmacValue = "encryptedHmacValue";
        public const string uri = "uri";
        public const string spinCount = "spinCount";
        public const string encryptedVerifierHashInput = "encryptedVerifierHashInput";
        public const string encryptedVerifierHashValue = "encryptedVerifierHashValue";
        public const string encryptedKeyValue = "encryptedKeyValue";
    }


    // Block keys for Agile defined in specification document
    public class BlockKey
    {
        public static byte[] EncryptedVerifierHashInput      = new byte[8] { 0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79 };
        public static byte[] EncryptedVerifierHashValue      = new byte[8] { 0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e };
        public static byte[] EncryptedKeyValue               = new byte[8] { 0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6 };
        public static byte[] EncryptedDataIntegritySalt      = new byte[8] { 0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6 };
        public static byte[] EncryptedDataIntegrityHmacValue = new byte[8] { 0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33 };
    }



    public class ChainingModes
    {
        public const string CBC = "ChainingModeCBC";
        public const string CFB = "ChainingModeCFB";
    }






    /// <summary>
    /// Class implements the code to decrypt an Office document encrypted using the Agile Encryption method
    /// </summary>
    public static class AgileEncryption
    {
        #region Decrypt the package

        /// <summary>
        /// This function assumes you have extract the EncryptionInfo & EncryptedPackage
        /// streams from the Office document which is an OLEStorage file
        /// </summary>
        /// <param name="password"></param>
        /// <param name="encryptionInfo"></param>
        /// <param name="encryptedPackage"></param>
        /// <returns></returns>
        static internal byte[] DecryptInternal(string password, byte[] encryptionInfo, byte[] encryptedPackage)
        {
            AgileEncryptionHeader docInfo = ParseEncryptionInfoFromBytes(encryptionInfo);
            if (docInfo == null) return null;

            HashAlgorithm hashAlg = docInfo.GetHashAlgorithm();
            if (hashAlg == null) return null;

            SymmetricAlgorithm cipher = docInfo.GetCipherAlgorithm();
            if (cipher == null) return null;

            try
            {
                // Verifier, 2.3.4.11-13
                if (!docInfo.VerifyPassword(password)) return null;

                // Generate encryption key (2.3.4.11). use different block key than for password verification
                var decryptedKeyValue = docInfo.GenerateEncryptionKey(password);

                // check Data Integrity for encryptedPackage (2.3.4.14)
                if (!docInfo.VerifyDataIntegrity(decryptedKeyValue, encryptedPackage)) return null;

                // finally decrypt the document
                // decrypt the document, 2.3.4.15
                var streamSize = (int)BitConverter.ToUInt64(encryptedPackage, 0);
                var encryptedChunk = encryptedPackage.Skip(8).ToArray();
                byte[] package = new byte[encryptedChunk.Length];  // at most length
                int SEGMENT_SIZE = 4096; // every 4K segment got decryption separately, with different IV inferred from segment index
                for (int i = 0; i < encryptedChunk.Length; i += SEGMENT_SIZE) // consider using LINQ Select and SelectMany?
                {
                    int segmentIndex = i / SEGMENT_SIZE;
                    int actualSize = (encryptedChunk.Length - i) >= SEGMENT_SIZE ? SEGMENT_SIZE : (encryptedChunk.Length - i);
                    byte[] segment = new byte[actualSize];
                    Array.Copy(encryptedChunk, i, segment, 0, segment.Length);

                    // Create an IV. The technique is documented here 2.3.4.10.
                    var iv = AgileEncryptionHeader.GenerateIV(hashAlg, docInfo.kdSaltValue, BitConverter.GetBytes((int)segmentIndex), docInfo.kdBlockSize);
                    segment = SymmetricCipher.Decrypt(cipher, decryptedKeyValue, iv, segment);

                    Array.Copy(segment, 0, package, i, segment.Length);
                }
                return package.Take(streamSize).ToArray(); // plaintext length may be smaller than ciphertext length
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }

        #endregion



        // parse encryptionInfo stream for office 2010 Agile, in XML format
        public static AgileEncryptionHeader ParseEncryptionInfoFromBytes(byte[] encryptionInfo)
        {
            if (encryptionInfo == null) return null;

            AgileEncryptionHeader docInfo = new AgileEncryptionHeader();

            XDocument xmldoc = null;

            using (System.IO.MemoryStream encryptionInfoStream = new System.IO.MemoryStream(encryptionInfo))
            {
                System.IO.BinaryReader reader = new System.IO.BinaryReader(encryptionInfoStream);

                // version
                docInfo.versionMajor = reader.ReadUInt16();
                docInfo.versionMinor = reader.ReadUInt16();
                if (docInfo.versionMajor != 0x04 && docInfo.versionMinor != 0x04)
                {
                    return null;
                }

                // flags
                docInfo.encryptionFlags = (EncryptionFlags)reader.ReadUInt32();
                if (docInfo.encryptionFlags != EncryptionFlags.fAgile)
                {
                    return null; // Encryption flag is not consistent with Agile encryption type
                }

                // The rest of stream is Xml
                #region Load the Xml
                using (var xmlReader = XmlReader.Create(encryptionInfoStream))
                {
                    xmldoc = XDocument.Load(xmlReader);

                    // should we grab a schema so the XDocument can be validated?
                    /*
                    try
                    {
                        using (var stm = Assembly.GetExecutingAssembly().GetManifestResourceStream("CipherBox.Office.Properties.AgileXmlEncryptionDescriptor.xsd"))
                        {
                            System.Xml.Schema.XmlSchemaSet set = new XmlSchemaSet();
                            set.Add( AgileEncryption.XmlRootUri, XmlReader.Create(stm));
                            bool validationErrors = false;
                            List<string> errors = new List<string>();
                            xmldoc.Validate(set, (sender, args) =>
                            {
                                validationErrors = true;
                                errors.Add(args.Message);
                            });

                            if (validationErrors)
                            {
                                Console.WriteLine(string.Format("The encrypted document's EncryptionInfo failed schema validation:\n{0}", string.Join("\n", errors.ToArray())));
                                return null;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(string.Format("An error occured reading the EncryptionInfo.  The problem is: {0}", ex.Message));
                        return null;
                    }
                    */
                }
                #endregion
            }

            #region Parse the xml information

            try
            {
                XElement keyData = xmldoc.Root.Element(XName.Get(XmlTokenNames.keyData, XmlTokenNames.XmlRootUri));
                if (keyData == null)
                {
                    Console.WriteLine("keyData element is missing");
                    return null;
                }

                docInfo.kdSaltSize = keyData.Attribute(XmlTokenNames.saltSize).ToInt(0);
                docInfo.kdBlockSize = keyData.Attribute(XmlTokenNames.blockSize).ToInt(0);
                docInfo.kdKeyBits = keyData.Attribute(XmlTokenNames.keyBits).ToInt(0);
                docInfo.kdHashSize = keyData.Attribute(XmlTokenNames.hashSize).ToInt(0);
                docInfo.kdCipherAlgorithm = keyData.Attribute(XmlTokenNames.cipherAlgorithm).ValueOrDefault(CipherAlgorithms.AES);
                docInfo.kdCipherChaining = keyData.Attribute(XmlTokenNames.cipherChaining).ValueOrDefault(ChainingModes.CBC);
                docInfo.kdHashAlgorithm = keyData.Attribute(XmlTokenNames.hashAlgorithm).ValueOrDefault(HashAlgorithms.SHA512);
                string kdSaltValue = keyData.Attribute(XmlTokenNames.saltValue).ValueOrDefault("");
                docInfo.kdSaltValue = Convert.FromBase64String(kdSaltValue);

                XElement dataIntegrity = xmldoc.Root.Element(XName.Get(XmlTokenNames.dataIntegrity, XmlTokenNames.XmlRootUri));
                if (dataIntegrity == null)
                {
                    Console.WriteLine("dataIntegrity element is missing");
                    return null;
                }

                string encryptedHmacKey = dataIntegrity.Attribute(XmlTokenNames.encryptedHmacKey).ValueOrDefault("");
                docInfo.encryptedHmacKey = Convert.FromBase64String(encryptedHmacKey);
                string encryptedHmacValue = dataIntegrity.Attribute(XmlTokenNames.encryptedHmacValue).ValueOrDefault("");
                docInfo.encryptedHmacValue = Convert.FromBase64String(encryptedHmacValue);

                XElement passwordKeyEncryptor = xmldoc.Root.Element(XName.Get(XmlTokenNames.keyEncryptors, XmlTokenNames.XmlRootUri));
                if (passwordKeyEncryptor == null)
                {
                    Console.WriteLine("keyEncryptors element is missing");
                    return null;
                }

                var ke = passwordKeyEncryptor.Element(XName.Get(XmlTokenNames.keyEncryptor, XmlTokenNames.XmlRootUri));
                if (ke == null)
                {
                    Console.WriteLine("Key Encryptor element is missing");
                    return null;
                }

                ke = ke.Descendants().FirstOrDefault();
                if (ke == null)
                {
                    Console.WriteLine("Password Key Encryptor element is missing");
                    return null;
                }

                docInfo.pkeSpinCount = ke.Attribute(XmlTokenNames.spinCount).ToInt(0);
                docInfo.pkeSaltSize = ke.Attribute(XmlTokenNames.saltSize).ToInt(0);
                docInfo.pkeBlockSize = ke.Attribute(XmlTokenNames.blockSize).ToInt(0);
                docInfo.pkeKeyBits = ke.Attribute(XmlTokenNames.keyBits).ToInt(0);
                docInfo.pkeHashSize = ke.Attribute(XmlTokenNames.hashSize).ToInt(0);
                docInfo.pkeCipherAlgorithm = ke.Attribute(XmlTokenNames.cipherAlgorithm).ValueOrDefault(CipherAlgorithms.AES);
                docInfo.pkeCipherChaining = ke.Attribute(XmlTokenNames.cipherChaining).ValueOrDefault(ChainingModes.CBC);
                docInfo.pkeHashAlgorithm = ke.Attribute(XmlTokenNames.hashAlgorithm).ValueOrDefault(HashAlgorithms.SHA512);
                string pkeSaltValue = ke.Attribute(XmlTokenNames.saltValue).ValueOrDefault("");
                docInfo.pkeSaltValue = Convert.FromBase64String(pkeSaltValue);
                string encryptedVerifierHashInput = ke.Attribute(XmlTokenNames.encryptedVerifierHashInput).ValueOrDefault("");
                docInfo.pkeEncryptedVerifierHashInput = Convert.FromBase64String(encryptedVerifierHashInput);
                string encryptedVerifierHashValue = ke.Attribute(XmlTokenNames.encryptedVerifierHashValue).ValueOrDefault("");
                docInfo.pkeEncryptedVerifierHashValue = Convert.FromBase64String(encryptedVerifierHashValue);
                string pkeEncryptedKeyValue = ke.Attribute(XmlTokenNames.encryptedKeyValue).ValueOrDefault("");
                docInfo.pkeEncryptedKeyValue = Convert.FromBase64String(pkeEncryptedKeyValue);
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Parsing EncryptionInfo error: {0}", ex.Message));
                return null;
            }

            #endregion

            return docInfo;
        }


        private static bool SetPassword(string password, ref AgileEncryptionHeader config)
        {
            SymmetricAlgorithm cipher = config.GetCipherAlgorithm();
            if (cipher == null) return false;

            HashAlgorithm hashAlg = config.GetHashAlgorithm();
            if (hashAlg == null) return false;

            // new header by default already has some values. 
            // we still need to do:
            //  (1) set password
            //   need random pke salt
            //   need a random key and encrypted to pkeEncryptedKeyValue
            //   need a random verifier and encrypted to pkeEncryptedVerifierHashInput, pkeEncryptedVerifierHashValue, for password verification

            //  (2)
            //   need random kd salt, for data encryption and integrity check

            //  (3) add data integrity check ( require document encryptedPackage, not for now )
            //   need to generate encryptedHmacKey and encryptedHmacValue, for data integrity check
            
            
            config.pkeSaltValue = IVGenerator.RandomIV(config.pkeSaltSize);

            byte[] keyValue = IVGenerator.RandomIV(config.kdKeyBits >> 3); // will be encrypted to pkeEncryptedKeyValue
            var cipherKey = config.GenerateEncryptionKey(password, BlockKey.EncryptedKeyValue);
            config.pkeEncryptedKeyValue = SymmetricCipher.Encrypt(cipher, 
                cipherKey, 
                config.pkeSaltValue,   // as IV
                keyValue);


            byte[] verifierHashInput = IVGenerator.RandomIV(config.pkeSaltSize);
            var verifierHashInput_cipherKey = config.GenerateEncryptionKey(password, BlockKey.EncryptedVerifierHashInput);
            config.pkeEncryptedVerifierHashInput = SymmetricCipher.Encrypt(cipher,
                verifierHashInput_cipherKey,
                config.pkeSaltValue, // as IV
                verifierHashInput);

            var hash = hashAlg.ComputeHash(verifierHashInput);

            var verifierHashValue_cipherKey = config.GenerateEncryptionKey(password, BlockKey.EncryptedVerifierHashValue);
            config.pkeEncryptedVerifierHashValue = SymmetricCipher.Encrypt(cipher,
                verifierHashValue_cipherKey,
                config.pkeSaltValue, // as IV
                hash);

            // kd salt is not required for password verification, but for data encryption and integrity check
            config.kdSaltValue = IVGenerator.RandomIV(config.kdSaltSize);
            
            return true;
        }


        private static bool SetDataIntegrityCheck(byte[] plainKeyValue, byte[] encryptedPackage, ref AgileEncryptionHeader config)
        {
            HashAlgorithm hashAlg = config.GetHashAlgorithm();
            if (hashAlg == null) return false;

            SymmetricAlgorithm cipher = config.GetCipherAlgorithm();
            if (cipher == null) return false;

            byte[] salt = IVGenerator.RandomIV(config.kdHashSize);

            // Encrypt the salt value
            byte[] ivDataIntegritySalt = AgileEncryptionHeader.GenerateIV(hashAlg, config.kdSaltValue, BlockKey.EncryptedDataIntegritySalt, config.kdBlockSize);
            config.encryptedHmacKey = SymmetricCipher.Encrypt(cipher,
                plainKeyValue,
                ivDataIntegritySalt,
                salt);

            // further use the salt as hash key to HMAC(the encrypted document)
            KeyedHashAlgorithm hmacAlg = KeyedHashAlgorithm.Create("HMAC" + config.kdHashAlgorithm);  // note: Net2.0 only supports HMACSHA1 and MACTripleDES, while NET3.5 for all
            hmacAlg.Key = salt.Take(config.kdHashSize).ToArray();
            var hmac = hmacAlg.ComputeHash(encryptedPackage);

            // Encrypt the HMAC value
            byte[] ivDataIntegrityHash = AgileEncryptionHeader.GenerateIV(hashAlg, config.kdSaltValue, BlockKey.EncryptedDataIntegrityHmacValue, config.kdBlockSize);
            config.encryptedHmacValue = SymmetricCipher.Encrypt(cipher,
                plainKeyValue,    // as cipher key
                ivDataIntegrityHash,  // as IV
                hmac);
            
            return true;
        }
        


        // password key encryptor part for XML
        public static byte[] CreateEncryptionInfo(AgileEncryptionHeader config)
        {
            var stream = new MemoryStream();

            // Write version, version, and flags
            stream.WriteInt16(4);
            stream.WriteInt16(4);
            stream.WriteInt32(0x40);

            // Generate the crypto xml
            var writer = new XmlTextWriter(stream, System.Text.Encoding.UTF8);
            using (writer)
            {
                writer.WriteStartDocument();

                // <encryption>
                writer.WriteStartElement(XmlTokenNames.encryption, XmlTokenNames.XmlRootUri);

                // <keyData>
                writer.WriteStartElement(XmlTokenNames.keyData, XmlTokenNames.XmlRootUri);
                writer.WriteAttributeString(XmlTokenNames.blockSize, config.kdBlockSize.ToString());
                writer.WriteAttributeString(XmlTokenNames.saltSize, config.kdSaltSize.ToString());
                writer.WriteAttributeString(XmlTokenNames.keyBits, config.kdKeyBits.ToString());
                writer.WriteAttributeString(XmlTokenNames.hashSize, config.kdHashSize.ToString());
                writer.WriteAttributeString(XmlTokenNames.cipherAlgorithm, config.kdCipherAlgorithm);
                writer.WriteAttributeString(XmlTokenNames.cipherChaining, config.kdCipherChaining);
                writer.WriteAttributeString(XmlTokenNames.hashAlgorithm, config.kdHashAlgorithm);
                writer.WriteAttributeString(XmlTokenNames.saltValue, Convert.ToBase64String(config.kdSaltValue, Base64FormattingOptions.None));
                writer.WriteEndElement();
                // </keyData>

                if (config.encryptedHmacKey != null && config.encryptedHmacValue != null)
                {
                    // <dataIntegrity>
                    writer.WriteStartElement(XmlTokenNames.dataIntegrity, XmlTokenNames.XmlRootUri);
                    writer.WriteAttributeString(XmlTokenNames.encryptedHmacKey, Convert.ToBase64String(config.encryptedHmacKey, Base64FormattingOptions.None));
                    writer.WriteAttributeString(XmlTokenNames.encryptedHmacValue, Convert.ToBase64String(config.encryptedHmacValue, Base64FormattingOptions.None));
                    writer.WriteEndElement();
                    // </dataIntegrity>
                }


                // <keyEncryptors>
                writer.WriteStartElement(XmlTokenNames.keyEncryptors, XmlTokenNames.XmlRootUri);
                {
                    // <keyEncryptor>
                    writer.WriteStartElement(XmlTokenNames.keyEncryptor, XmlTokenNames.XmlRootUri);
                    writer.WriteAttributeString(XmlTokenNames.uri, XmlTokenNames.XmlRootUriPKE);
                    {
                        // <p:encryptedKey>
                        writer.WriteStartElement(XmlTokenNames.encryptedKey, XmlTokenNames.XmlRootUriPKE);
                        writer.WriteAttributeString(XmlTokenNames.spinCount, config.pkeSpinCount.ToString());
                        writer.WriteAttributeString(XmlTokenNames.saltSize, config.pkeSaltSize.ToString());
                        writer.WriteAttributeString(XmlTokenNames.blockSize, config.pkeBlockSize.ToString());
                        writer.WriteAttributeString(XmlTokenNames.keyBits, config.pkeKeyBits.ToString());
                        writer.WriteAttributeString(XmlTokenNames.cipherAlgorithm, config.pkeCipherAlgorithm);
                        writer.WriteAttributeString(XmlTokenNames.cipherChaining, config.pkeCipherChaining);
                        writer.WriteAttributeString(XmlTokenNames.hashAlgorithm, config.pkeHashAlgorithm);
                        writer.WriteAttributeString(XmlTokenNames.hashSize, config.pkeHashSize.ToString());
                        writer.WriteAttributeString(XmlTokenNames.saltValue, Convert.ToBase64String(config.pkeSaltValue, Base64FormattingOptions.None));
                        writer.WriteAttributeString(XmlTokenNames.encryptedVerifierHashInput, Convert.ToBase64String(config.pkeEncryptedVerifierHashInput, Base64FormattingOptions.None));
                        writer.WriteAttributeString(XmlTokenNames.encryptedVerifierHashValue, Convert.ToBase64String(config.pkeEncryptedVerifierHashValue, Base64FormattingOptions.None));
                        writer.WriteAttributeString(XmlTokenNames.encryptedKeyValue, Convert.ToBase64String(config.pkeEncryptedKeyValue, Base64FormattingOptions.None));
                        writer.WriteEndElement();
                        // </p:encryptedKey>
                    }
                    writer.WriteEndElement();
                    // </keyEncryptor>
                }
                writer.WriteEndElement();
                // </keyEncryptors>

                writer.WriteEndElement();
                // </encryption>

                writer.WriteEndDocument();
                writer.Flush();
            }

            byte[] result = stream.ToArray();
            //Console.WriteLine("EncryptionInfo:" + System.Text.Encoding.UTF8.GetString(result));
            return result;
        }



        #region Encrypt the package

        // refer to : standard encryption function
        // Encrypts a package (zip) file using a supplied password and returns 
        // an array to create an encryption information stream and a byte array 
        // of the encrypted package.
        public static void EncryptPackage(byte[] packageContents, string password, out byte[] encryptionInfo, out byte[] encryptedPackage)
        {
            encryptionInfo = null;
            encryptedPackage = null;

            // generate a sample Agile encryption header based on password, default is AES256 CBC and SHA512
            AgileEncryptionHeader docInfo = new AgileEncryptionHeader();

            // set verifier values for password verification
            SetPassword(password, ref docInfo);

            HashAlgorithm hashAlg = docInfo.GetHashAlgorithm();
            if (hashAlg == null) return;
            SymmetricAlgorithm cipher = docInfo.GetCipherAlgorithm();
            if (cipher == null) return;


            // save the length of the original plain package
            int originalLength = packageContents.Length;

            // Pad the array to the nearest 16 byte boundary
            int remainder = packageContents.Length % docInfo.kdBlockSize;
            if (remainder != 0)
            {
                byte[] tempContents = new byte[packageContents.Length + docInfo.kdBlockSize - remainder]; // pad with zeores
                Array.Copy(packageContents, tempContents, packageContents.Length);
                packageContents = tempContents;
            }

            // now encrypt on package contents
            #region Encrypt the document, 2.3.4.15
            byte[] key = docInfo.GenerateEncryptionKey(password);
            byte[] encryptedResult = new byte[packageContents.Length];
            int SEGMENT_SIZE = 4096; // every 4K segment got encryption separately, with different IV inferred from segment index
            for (int i = 0; i < packageContents.Length; i += SEGMENT_SIZE)
            {
                int segmentIndex = i / SEGMENT_SIZE;
                int actualSize = (packageContents.Length - i >= SEGMENT_SIZE) ? SEGMENT_SIZE : (packageContents.Length - i);
                byte[] segment = new byte[actualSize];
                Array.Copy(packageContents, i, segment, 0, segment.Length);

                var iv = AgileEncryptionHeader.GenerateIV(hashAlg, docInfo.kdSaltValue, BitConverter.GetBytes((int)segmentIndex), docInfo.kdBlockSize);
                segment = SymmetricCipher.Encrypt(cipher, key, iv, segment);

                Array.Copy(segment, 0, encryptedResult, i, segment.Length); // assume encrypted segment length = segment length
            }
            #endregion

            // Need to prepend the original package size as a Int64 (8 byte) field
            encryptedPackage = new byte[encryptedResult.Length + 8];
            Array.Copy(BitConverter.GetBytes((long)originalLength), encryptedPackage, 8);
            Array.Copy(encryptedResult, 0, encryptedPackage, 8, encryptedResult.Length);


            // add data integrity check to encryptionInfo header
            SetDataIntegrityCheck(key, encryptedPackage, ref docInfo);

            // finally can generate encryptionInfo XML header
            encryptionInfo = CreateEncryptionInfo(docInfo);  
        }



        #endregion


    }
}

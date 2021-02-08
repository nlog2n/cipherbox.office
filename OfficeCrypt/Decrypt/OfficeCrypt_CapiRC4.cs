// Capi RC4 for office2002/2003: RC4 + SHA-1

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

using CipherBox.Office.OLE;
using CipherBox.Office.Common;

namespace CipherBox.Office.CryptoAPI
{
    public static class RC4EncryptionCryptoAPI
    {
        // encryptionheader may be the begin of 1Table, or end of ppt document
        public static RC4EncryptionCryptoAPIHeader ParseRC4CryptoAPIEncryptionHeader(byte[] encryptionInfo)
        {
            if (encryptionInfo == null) return null;

            try
            {
                using (System.IO.MemoryStream ms = new System.IO.MemoryStream(encryptionInfo))
                {
                    System.IO.BinaryReader reader = new System.IO.BinaryReader(ms);

                    RC4EncryptionCryptoAPIHeader info = new RC4EncryptionCryptoAPIHeader();

                    // version
                    info.versionMajor = reader.ReadUInt16();
                    info.versionMinor = reader.ReadUInt16();
                    if (!((info.versionMajor == 2 || info.versionMajor == 3 || info.versionMajor == 4)
                           && info.versionMinor == 2
                         )
                        )
                    {
                        return null; // wrong version
                    }

                    // flags
                    info.encryptionFlags = (EncryptionFlags)reader.ReadUInt32();
                    if ((info.encryptionFlags & EncryptionFlags.fCryptoAPI) == 0) // cryptoAPI 0x04
                    {
                        Console.WriteLine("incorrect flags");
                        return null;
                    }

                    // Get the size of the header
                    uint uHeaderSize = reader.ReadUInt32();

                    #region Now read in encryption header

                    byte[] headerBuf = reader.ReadBytes((int)uHeaderSize);

                    // Check the parameters
                    uint uFlags2 = BitConverter.ToUInt32(headerBuf, 0);
                    if (info.encryptionFlags != (EncryptionFlags)uFlags2)
                    {
                        Console.WriteLine("EncryptionHeader.Flags incorrect");
                        return null;
                    }

                    // SizeExtra has to be 0
                    uint uSizeExtra = BitConverter.ToUInt32(headerBuf, 4);
                    if (uSizeExtra != 0)
                    {
                        Console.WriteLine("EncryptionHeader.SizeExtra incorrect");
                        return null;
                    }

                    // Check algID
                    uint algId = BitConverter.ToUInt32(headerBuf, 8);
                    if (algId != (uint)AlgId.RC4) // 0x00006801
                    {
                        Console.WriteLine("EncryptionHeader.AlgID incorrect");
                        return null;
                    }

                    // Check AlgIdHash - must be SHA1
                    uint algIdHash = BitConverter.ToUInt32(headerBuf, 12);
                    if (algIdHash != (uint)AlgHashId.SHA1) // 0x00008004
                    {
                        Console.WriteLine("EncryptionHeader.AlgIDHash incorrect");
                        return null;
                    }

                    // Encryption key size
                    info.keySize = BitConverter.ToUInt32(headerBuf, 16);
                    if (info.keySize != 0 && (info.keySize < 0x28 || info.keySize > 0x80 || (info.keySize % 8) != 0))
                    {
                        Console.WriteLine("EncryptionHeader.KeySize incorrect");
                        return null;
                    }

                    // value 0 means 40-bit RC4
                    if (info.keySize == 0)
                    {
                        info.keySize = 40;
                    }

                    info.providerType = (ProviderType)BitConverter.ToUInt32(headerBuf, 20);
                    if (info.providerType != ProviderType.RC4)
                    {
                        Console.WriteLine("EncryptionHeader.ProviderType incorrect");
                        return null;
                    }

                    uint reserved2 = BitConverter.ToUInt32(headerBuf, 28);
                    if (reserved2 != 0)
                    {
                        Console.WriteLine("EncryptionHeader.Reserved2 incorrect");
                        return null;
                    }

                    info.CSPName = System.Text.UnicodeEncoding.Unicode.GetString(headerBuf, 32, (int)uHeaderSize - 32);
                    #endregion

                    #region parse the EncryptionVerifier
                    // Check that the verifier size makes sense
                    // Encryption verifier, includes: saltSize(4Bytes), salt(16B), encryptedVerifier(16B), verifierHashSize(4B), and encryptedVerifierHash(20B)
                    int verifierSize = (int)(encryptionInfo.Length - uHeaderSize - 12);
                    if (verifierSize < 4 + 16 + 16 + 4 + 20)
                    {
                        Console.WriteLine("Verifier Size incorrect");
                        return null;
                    }
                    byte[] verifierBuf = reader.ReadBytes(verifierSize); // Note - in case of RC4, there could be additional data past the encryption header and verifier

                    // Check the salt size, copy the salt
                    info.saltSize = BitConverter.ToUInt32(verifierBuf, 0);
                    if (info.saltSize != 16)
                    {
                        Console.WriteLine("SaltSize invalid");
                        return null;
                    }
                    info.salt = new byte[16];
                    Array.Copy(verifierBuf, 4, info.salt, 0, 16);

                    info.encryptedVerifier = new byte[16];
                    Array.Copy(verifierBuf, 20, info.encryptedVerifier, 0, 16);

                    info.verifierHashSize = BitConverter.ToUInt32(verifierBuf, 36);
                    if (info.verifierHashSize != 20)
                    {
                        Console.WriteLine("VerifierHashSize invalid");
                        return null;
                    }
                    info.encryptedVerifierHash = new byte[20];
                    Array.Copy(verifierBuf, 40, info.encryptedVerifierHash, 0, info.encryptedVerifierHash.Length);
                    #endregion

                    return info;
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

/******************************************************************************* 
 * 
 *  Encryption info for Office Open XML files
 * 
 * Algorithms in this code file are based on the MS-OFFCRYPT.PDF provided by
 * Microsoft as part of its Open Specification Promise (OSP) program and which 
 * is available here:
 * 
 * http://msdn.microsoft.com/en-us/library/cc313071.aspx
 * 
 */


using System;
using System.Collections.Generic;
using System.Text;

using CipherBox.Office.Common;
using CipherBox.Cryptography.Net;

namespace CipherBox.Office.Standard
{
	/// <summary>
	/// This class tries to implement the algorithms documents in MS-OFFCRYPTO 2.3.4.7-2.3.4.9.
	/// 
	/// It is intended to be used with .NET 3.0 or later and it is assumes the WindowsBase 
	/// assembly is referenced by the project to include the System.IO.Packaging namespace.
	/// </summary>
	/// <remarks>
	/// -------------------------------------------------------------------------
	///
	/// This is the content of the EncryptionInfo stream created by Excel 2007
	/// when saving a password protected xlsb file.  The password used is:
	/// "password"
	///
	/// 00000000 03 00 02 00                                         				Version
	/// 00000000             24 00 00 00						            		Flags (fCryptoAPI + fAES)
	/// 00000000                         A4 00 00 00			                	Header length
	/// 00000000                                     24 00 00 00                 	Flags (again)
	/// 00000010 00 00 00 00                                         				Size extra
	/// 00000010             0E 66 00 00                                 			Alg ID 0x0000660E = 128-bit AES,0x0000660F  192-bit AES, 0x00006610  256-bit AES
	/// 00000010                         04 80 00 00                         		Alg hash ID 0x00008004 SHA1
	/// 00000010                                     80 00 00 00                 	Key size AES = 0x00000080, 0x000000C0, 0x00000100  128, 192 or 256-bit 
	/// 00000020 18 00 00 00                                         				Provider type 0x00000018 AES
	/// 00000020             A0 C7 DC 02 00 00 00 00                         		Reserved
	/// 00000020                                     4D 00 69 00             M?i?	CSP Name
	/// 00000030 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 c?r?o?s?o?f?t? ?
	/// 00000040 45 00 6E 00 68 00 61 00 6E 00 63 00 65 00 64 00 E?n?h?a?n?c?e?d?
	/// 00000050 20 00 52 00 53 00 41 00 20 00 61 00 6E 00 64 00  ?R?S?A? ?a?n?d?
	/// 00000060 20 00 41 00 45 00 53 00 20 00 43 00 72 00 79 00  ?A?E?S? ?C?r?y?
	/// 00000070 70 00 74 00 6F 00 67 00 72 00 61 00 70 00 68 00 p?t?o?g?r?a?p?h?
	/// 00000080 69 00 63 00 20 00 50 00 72 00 6F 00 76 00 69 00 i?c? ?P?r?o?v?i?
	/// 00000090 64 00 65 00 72 00 20 00 28 00 50 00 72 00 6F 00 d?e?r? ?(?P?r?o?
	/// 000000A0 74 00 6F 00 74 00 79 00 70 00 65 00 29 00 00 00 t?o?t?y?p?e?)
	/// 
	/// 000000B0 10 00 00 00                                         				Salt size
	/// 000000B0             90 AC 68 0E 76 F9 43 2B 8D 13 B7 1D                 	Salt
	/// 000000C0 B7 C0 FC 0D                                     			
	/// 000000C0             43 8B 34 B2 C6 0A A1 E1 0C 40 81 CE                 	Encrypted verifier
	/// 000000D0 83 78 F4 7A                                    
	/// 000000D0             14 00 00 00                                 			Hash length
	/// 000000D0                         48 BF F0 D6 C1 54 5C 40                 	EncryptedVerifierHash
	/// 000000E0 FE 7D 59 0F 8A D7 10 B4 C5 60 F7 73 99 2F 3C 8F 
	/// 000000F0 2C F5 6F AB 3E FB 0A D5                        
	///
	/// -------------------------------------------------------------------------
	/// </remarks>



    public class StandardEncryptionHeader : IVerifier
	{
		#region Class variables

		public ushort			versionMajor		= 3;
		public ushort			versionMinor		= 2;
        public EncryptionFlags  encryptionFlags		= EncryptionFlags.fCryptoAPI | EncryptionFlags.fAES;

        // Encryption header        
		public uint			    sizeExtra				= 0;
        public AlgId			algId					= AlgId.AES128;
		public AlgHashId		algHashId				= AlgHashId.SHA1;
		public uint				keySize					= 0x80; // in bits,  AES = 0x00000080, 0x000000C0, 0x00000100  for 128, 192 or 256-bit 
		public ProviderType	    providerType			= ProviderType.AES;
        public string           CSPName                 = ProvName.MS_ENH_RSA_AES_PROV_EXT; 

		// Encryption verifier
		public uint				saltSize				= 0x10;  // Default
		public byte[]			salt					= null;
		public byte[]			encryptedVerifier		= null;
		public uint				verifierHashSize		= 0x14;  // in bytes, 
		public byte[]			encryptedVerifierHash	= null;

        // for content, optional
		public byte[]			encryptedPackage		= null;  

        // constant spin count
        public int spinCount = 50000; // Default to the Standard spin count

		#endregion


        /// <summary>
        /// Implements (tries to) the hash key generation algorithm in section 2.3.4.7
        /// The 
        /// </summary>
        /// <param name="salt">A salt (taken from the EncrptionInfo stream)</param>
        /// <param name="password">The password used to decode the stream</param>
        /// <param name="sha1HashSize">Size of the hash (taken from theEncrptionInfo stream)</param>
        /// <param name="keySize">The keysize (taken from theEncrptionInfo stream)</param>
        /// <returns>The derived encryption key byte array</returns>
        public byte[] GeneratePasswordKey(string password)
        {
            byte[] hashBuf = null;

            try
            {
                SHAOne sha1 = new SHAOne();

                // H(0) = H(salt, password);
                // Use a unicode form of the password
                byte[] passwordBuf = System.Text.UnicodeEncoding.Unicode.GetBytes(password);
                hashBuf = sha1.ComputeHash(this.salt, passwordBuf);

                //Console.WriteLine("H0=" + BitConverter.ToString(hashBuf, 0, hashBuf.Length));

                for (int i = 0; i < 50000; i++) // spinCount
                {
                    // Generate each hash in turn
                    // H(n) = H(i, H(n-1))
                    hashBuf = sha1.ComputeHash(System.BitConverter.GetBytes(i), hashBuf); // SHA1(int32 || buf), little-endian uint32 expected

                    //if (i < 5 || i == 49999)
                    //    Console.WriteLine("H" + i.ToString() + "=" + BitConverter.ToString(hashBuf, 0, hashBuf.Length));
                }

                // Finally, append "block" (0) to H(n)
                hashBuf = sha1.ComputeHash(hashBuf, System.BitConverter.GetBytes((int)0));  // 4-byte 0

                //Console.WriteLine("Hfinal=" + BitConverter.ToString(hashBuf, 0, hashBuf.Length));

                // do XOR obfuscation and more hash to derive the key
                byte[] derivedKey = new byte[64];

                // This is step 4a in 2.3.4.7 of MS_OFFCRYPT version 1.0
                // and is required even though the notes say it should be 
                // used only when the encryption algorithm key > hash length.

                // X1
                for (int i = 0; i < derivedKey.Length; i++)
                {
                    derivedKey[i] = (byte)(i < hashBuf.Length ? 0x36 ^ hashBuf[i] : 0x36);
                }
                byte[] X1 = sha1.ComputeHash(derivedKey);

                // X2
                for (int i = 0; i < derivedKey.Length; i++)
                {
                    derivedKey[i] = (byte)(i < hashBuf.Length ? 0x5C ^ hashBuf[i] : 0x5C);
                }
                byte[] X2 = sha1.ComputeHash(derivedKey);

                sha1.Clear();

                // X3 = X1 || X2
                byte[] X3 = new byte[X1.Length + X2.Length];
                Array.Copy(X1, 0, X3, 0, X1.Length);
                Array.Copy(X2, 0, X3, X1.Length, X2.Length);

                /*
                if (doc.keySize / 8 < doc.verifierHashSize)  // can return X1 directly for smaller key size
                {
                    X3 = X1;
                }
                */

                // Should handle the case of longer key lengths as shown in 2.3.4.9
                // Grab the key length bytes of the final hash as the encrypytion key
                byte[] final = new byte[this.keySize / 8];
                Array.Copy(X3, final, final.Length);
                return final;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return null;
        }


        /// <summary>
        /// Implements the password verifier process
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedVerifier">An array of the encryptedVerifier bytes</param>
        /// <param name="encryptedVerifierHash">An array of the encryptedVerifierHash bytes</param>
        /// <returns>True if the password is a match</returns>
        private bool VerifyPasswordKey(byte[] key)
        {
            // Decrypt the encrypted verifier...
            byte[] decryptedVerifier = AESCipherEcbNoPad.Decrypt(this.encryptedVerifier, key);

            // Truncate
            byte[] data = new byte[16];
            Array.Copy(decryptedVerifier, data, data.Length);
            decryptedVerifier = data;
            //Console.WriteLine("decryptedVerifier=" + BitConverter.ToString(decryptedVerifier, 0, decryptedVerifier.Length));

            // ... and hash
            byte[] decryptedVerifierHash = AESCipherEcbNoPad.Decrypt(this.encryptedVerifierHash, key);

            // Hash the decrypted verifier (2.3.4.9)
            SHAOne sha1 = new SHAOne();
            byte[] checkHash = sha1.ComputeHash(decryptedVerifier);
            sha1.Clear();
            //Console.WriteLine("computedVerifierHash =" + BitConverter.ToString(checkHash, 0, checkHash.Length));

            //Console.WriteLine("decryptedVerifierHash=" + BitConverter.ToString(decryptedVerifierHash, 0, decryptedVerifierHash.Length));

            // Check equality
            for (int i = 0; i < checkHash.Length; i++)
            {
                if (decryptedVerifierHash[i] != checkHash[i])
                    return false;
            }

            return true;
        }


        public bool VerifyPassword(string password)
        {
            byte[] encryptionKey;
            return VerifyPassword(password, out encryptionKey);
        }

        // for office OoXml2007
        public bool VerifyPassword(string password, out byte[] encryptionKey)
        {
            #region Encryption key generation
            encryptionKey = GeneratePasswordKey(password);  // need salt
            if (encryptionKey == null) return false;
            //Console.WriteLine("encryptionKey=" + BitConverter.ToString(encryptionKey, 0, encryptionKey.Length));
            #endregion

            #region Password verification
            if (!VerifyPasswordKey(encryptionKey)) // need encrypt parameters
            {
                //Console.WriteLine("Password verification failed");
                return false; //  throw new InvalidPasswordException("The password is not valid");
            }
            else
            {
                //Console.WriteLine("Password verification succeeded");
            }
            #endregion

            return true;
        }



        public string ToDisplayString()
        {
            string result = "\nEncryption type: Standard 2007";

            result += "\nVersion:" + versionMajor.ToString() + "." + versionMinor.ToString();
            result += "\nFlag:" + encryptionFlags.ToString();
            result += "\nAlgID:" + algId.ToString();
            result += "\nAlgHashID:" + algHashId.ToString();
            result += "\nKeySize:" + keySize.ToString();
            result += "\nProviderType:" + providerType.ToString();
            result += "\nCSPName:" + CSPName;
            result += "\nSaltSize:" + saltSize.ToString();
            result += "\nSalt:" + BitConverter.ToString(salt, 0, (int)saltSize);
            result += "\nEncryptedVerifier:" + BitConverter.ToString(encryptedVerifier, 0, 16);
            result += "\nEncryptedVerifierHash:" + BitConverter.ToString(encryptedVerifierHash, 0, 32); // (int)verifierHashSize);

            return result;
        }

	}
}

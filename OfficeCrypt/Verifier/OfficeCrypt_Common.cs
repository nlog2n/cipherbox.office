/*
 * Common definitions and data types for MS Office documents
 *  
 */

using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace CipherBox.Office.Common
{
    // Word FIB.base Example: 0x13 = 0001 0011 = <MLKJIHGF>
    [Flags]
    public enum FibBaseEncryptionFlags
    {
        fEncrypted = 1,           // F, 1 for encrypted 
        fWhichTblStm = 2,         // G, 1 for 1Table, and 0 for 0Table
        fReadOnlyRecommended = 4, // H,
        fWriteReservation = 8,    // I
        fExtChar = 0x10,          // J, MUST be 1
        fLoadOverride = 0x20,     // K
        fFarEast = 0x40,          // L
        fObfuscated = 0x80        // M if fEncrypted is 1, this bit of 1 means using obfuscation; otherwise ignored
    }


    public class StreamNames
    {
        public const string cs1TableStreamName = "1Table";   // for Office Binary
        public const string cs0TableStreamName = "0Table";   // for Office Binary

        public const string csWordDocumentStreamName = "WordDocument"; // for word
        public const string csDataStreamName = "Data";  // for word

        public const string csCurrentUser = "Current User";      // for powerpoint
        public const string csPowerPointDocument = "PowerPoint Document"; // for powerpoint
        public const string csEncryptedSummary = "EncryptedSummary"; // for encrypted powerpoint
        public const string csPicturesStreamName = "Pictures"; // for powerpoint

        public const string csWorkbookStreamName = "Workbook"; // for excel
        public const string csRevisionStreamName = "Revision Log"; // for excel, optional
        public const string csPivotCacheStorageName = "_SX_DB_CUR"; // for excel, optional


        public const string csEncryptionInfoStreamName = "EncryptionInfo";   // for OOXML: Standard and Agile
        public const string csEncryptedPackageStreamName = "EncryptedPackage"; // for OOXML: Standard and Agile
    }


    #region Enumerations for CryptoAPI

    [Flags]
    public enum EncryptionFlags
    {
        None = 0,
        Reserved1 = 1,	    // MUST be 0, and MUST be ignored.
        Reserved2 = 2,	    // MUST be 0, and MUST be ignored.
        fCryptoAPI = 4,	    // A flag that specifies whether CryptoAPI RC4 or [ECMA-376] encryption is used. MUST be 1 unless fExternal is 1. If fExternal is 1, MUST be 0. 
        fDocProps = 8,	    // MUST be 0 if document properties are encrypted. Encryption of document properties is specified in section 2.3.5.4. 
        fExternal = 0x10,	// If extensible encryption is used, MUST be 1. If this field is 1, all other fields in this structure MUST be 0. 
        fAES = 0x20,	// If the protected content is an [ECMA-376] document, MUST be 1. If the fAES bit is 1, the fCryptoAPI bit MUST also be 1.
        fAgile = 0x40
    }


    public enum AlgId
    {
        ByFlags = 0x00,
        RC4 = 0x00006801,
        AES128 = 0x0000660E,
        AES192 = 0x0000660F,
        AES256 = 0x00006610
    }

    public enum AlgHashId
    {
        Any = 0x00,
        RC4 = 0x00008000,
        SHA1 = 0x00008004
    }

    public enum ProviderType
    {
        Any = 0x00000000,
        RC4 = 0x00000001,
        AES = 0x00000018
    }


    public class ProvName
    {
        public const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0\0";
        public const string MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
        public const string MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";
        public const string MS_DEF_RSA_SIG_PROV = "Microsoft RSA Signature Cryptographic Provider";
        public const string MS_DEF_RSA_SCHANNEL_PROV = "Microsoft RSA SChannel Cryptographic Provider";
        public const string MS_DEF_DSS_PROV = "Microsoft Base DSS Cryptographic Provider";
        public const string MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider";
        public const string MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider";
        public const string MS_DEF_DH_SCHANNEL_PROV = "Microsoft DH SChannel Cryptographic Provider";
        public const string MS_SCARD_PROV = "Microsoft Base Smart Card Crypto Provider";
        public const string MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        public const string MS_ENH_RSA_AES_PROV_EXT = "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)\0";
    }

    #endregion




}

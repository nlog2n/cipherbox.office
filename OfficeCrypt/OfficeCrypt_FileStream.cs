using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

// so far only handle Office 2007+ files IO

// required: DecryptToArray, EncryptToStream, GetEncryptionInfo

using CipherBox.Office.Common;
using CipherBox.Office.OLE;
using CipherBox.Office.Standard;
using CipherBox.Office.Agile;
using CipherBox.Office.Legacy;
using CipherBox.Office.CryptoAPI;
using CipherBox.Office.Word;
using CipherBox.Office.Excel;
using CipherBox.Office.PowerPoint;
using CipherBox.Office.OoXML;
using CipherBox.Office.Utility;


namespace CipherBox.Office
{
    public class OfficeFileExtension
    {
        public const string DOC = ".doc";  // Office 97/2000 or 2002/2003: RC4 Legacy or CryptoAPI
        public const string PPT = ".ppt";  // Office 97/2000 or 2002/2003: RC4 CryptoAPI only
        public const string XLS = ".xls";  // Office 97/2000 or 2002/2003: RC4 Legacy or CryptoAPI

        public const string DOCX = ".docx"; // Office 2007 or 2010:  Standard or Agile
        public const string PPTX = ".pptx"; // Office 2007 or 2010:  Standard or Agile
        public const string XLSX = ".xlsx"; // Office 2007 or 2010:  Standard or Agile
        public const string XLSB = ".xlsb"; // Office 2007 or 2010:  Standard or Agile
    }

    
    // supported encryption types
    public enum ProtectionFlag
    {
        None,

        Protected,  // protected, but not sure which one => not supported yet

        Obfuscation,// xor
        LegacyRC4,  // doc
        CapiRC4,    // doc
        Standard,   // docx
        Agile,      // docx

        Unknown     // not sure protected or not
    }


    public enum OfficeCryptErrors
    {
        None,
        PasswordInvalid,
        FileNotFound,
        FileFormatIncorrect,
        OperationForbidden,
        DecryptionFailure,
        OperationUnsupported
    }



    public class OfficeCryptStream : IFileLocker
    {
        #region file signature
        // Compound File Binary file format for DOC, XLS, and PPT:
        // http://msdn.microsoft.com/en-us/library/cc313105.aspx
        // However, there is no binary specification for MDB.

        // ZIP_PK has been adopted as the package or container for several digital formats that represent a single document
        // or other logical unit but comprise multiple files. These include:
        //   Office Open XML (OOXML, standardized as ECMA 376 and ISO/IEC 29500)
        //   Office Document Format (ODF, version 1.0 from OASIS, later standardized as ISO/IEC 26300)
        //   Java ARchive (JAR, used to distribute software applications or libraries in the Java programming language)
        //   EPUB (for electronic publications, developed by the International Digital Publishing Forum).

        // for Office 2007 and above, the file itself is a zip package (with zip file header). 
        // but when it is encrypted into a stream in OLE file format, the file header becomes Compound File Binary.
        // for Office 97-2003, it uses OLE file format.
        static readonly byte[] FileHeaderOLE = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }; // for MS Compount file Binary file signature
        static readonly byte[] FileHeaderZip = new byte[] { 0x50, 0x4B, 0x03, 0x04 };  // for PK zip file signature, 0x03 0x04 means local file header
        #endregion

        string _filename = null;     // full path file name
        byte[] _contents = null;  // internal bytes for underlying file (encrypted or plaintext)
        byte[] _plaintext = null;  // plaintext or decrypted data
        public ProtectionFlag _pFlag = ProtectionFlag.None;
        IVerifier _encryptionInfo = null;

        string _password = null;
        string _oldpassword = null;

        OfficeCryptErrors _lasterror = OfficeCryptErrors.None;

        public string Password
        {
            get { return _password; }
            set
            {
                _oldpassword = _password;
                _password = value;

                
                if (string.IsNullOrEmpty(_password))  // no password
                {
                    _pFlag = ProtectionFlag.None;
                }
                else // choose applicable crypto algorithm
                {
                    if (_pFlag == ProtectionFlag.None)
                    {
                        FileInfo fi = new FileInfo(_filename);
                        if (fi.Extension == OfficeFileExtension.DOCX || fi.Extension == OfficeFileExtension.XLSX
                            || fi.Extension == OfficeFileExtension.PPTX || fi.Extension == OfficeFileExtension.XLSB)
                        {
                            _pFlag = ProtectionFlag.Standard; // or Agile?
                            //_pFlag = ProtectionFlag.Agile;
                        }
                        else if (fi.Extension == OfficeFileExtension.DOC)
                        {
                            _pFlag = ProtectionFlag.LegacyRC4; // or CapiRC4?
                        }
                        else if (fi.Extension == OfficeFileExtension.PPT)
                        {
                            _pFlag = ProtectionFlag.CapiRC4;  // CapiRC4 only
                        }
                        else if (fi.Extension == OfficeFileExtension.XLS)
                        {
                            _pFlag = ProtectionFlag.LegacyRC4; // or CapiRC4?
                        }

                        // others not yet supported yet
                    }
                }
            }
        }


        // open document, internally decrypt it if password-protected
        // return the plain file content in byte stream
        public byte[] Open(string filename, string password)
        {
            if (!Read(filename))
                return null;

            if (String.IsNullOrEmpty(password) && !(_pFlag == ProtectionFlag.None))
                return null;

            // Check if the file is actually encrypted or plaintext
            switch (_pFlag)
            {
                case ProtectionFlag.None:
                    this._plaintext = this._contents; // as plaintext
                    return this._plaintext; 

                case ProtectionFlag.Standard:
                case ProtectionFlag.Agile:
                    _plaintext = OoXMLParser.DecryptToBytes(_contents, password, _pFlag);
                    //_plaintext = OoXMLParser.DecryptToBytes(filename, password, _pFlag);  // cause sharing problem!
                    if (_plaintext != null)
                    {
                        // save password
                        this._oldpassword = this._password;
                        this._password = password;
                    }
                    return _plaintext;

                case ProtectionFlag.LegacyRC4:
                    RC4Encryption.Decrypt((RC4EncryptionHeader)this._encryptionInfo, password); // TODO: decryption not yet available
                    return null;

                case ProtectionFlag.CapiRC4:
                case ProtectionFlag.Obfuscation:
                    Console.WriteLine("warning: {0} open stream not yet supported.", _pFlag.ToString());
                    _lasterror = OfficeCryptErrors.OperationUnsupported;
                    return null;

                case ProtectionFlag.Protected:
                case ProtectionFlag.Unknown:
                default:
                    return null;
            }
        }

   



        /// <summary>
        /// Encrypt and write out to a new file stream.
        /// NOTE: Don't forget to call Close().
        /// If file exists, this overwrites it -- check before calling.
        /// </summary>
        /// <param name="filename"></param>
        public bool Save()
        {
            return SaveAs(_filename);
        }


        /// <summary>
        /// Encrypt and write out to storage stream.
        /// NOTE: Don't forget to call Close()
        /// </summary>
        public bool SaveAs(string filename)
        {
            // if same as before
            if (_oldpassword == _password && _filename == filename)
                return true;

            // error happened before
            if (_lasterror != OfficeCryptErrors.None)
                return false;

            // no plaintext obtained for save
            if (_plaintext == null)
            {
                _lasterror = OfficeCryptErrors.OperationForbidden;
                return false;
            }

            try
            {
                if (!string.IsNullOrEmpty(_password))  // password was set
                {
                    // apply to previous crypto algorithm
                    switch (_pFlag)
                    {
                        case ProtectionFlag.Standard:
                        case ProtectionFlag.Agile:
                            OoXMLParser.EncryptToFile(_plaintext, _password, filename, _pFlag);
                            break;

                        case ProtectionFlag.LegacyRC4:
                            RC4Encryption.EncryptToFile(_plaintext, _password, filename);
                            break;

                        case ProtectionFlag.CapiRC4:
                        case ProtectionFlag.Obfuscation:
                            Console.WriteLine("warning: {0} save not yet supported.", _pFlag.ToString());
                            _lasterror = OfficeCryptErrors.OperationUnsupported;
                            return false;
                        //break;

                        case ProtectionFlag.Protected:  // no action
                        case ProtectionFlag.Unknown:  // no action
                            return false;

                        case ProtectionFlag.None:
                        default:
                            // no protection though password was set. let's keep it same as before
                            File.WriteAllBytes(filename, _contents);
                            break;
                    }
                }
                else  // no password
                {
                    // write the plain stream contents to file
                    FileUtils.WriteAllBytes(filename, _plaintext);
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);  // may because of file access forbidden
                _lasterror = OfficeCryptErrors.OperationForbidden;
                return false;
            }
        }




        public bool Verify(string password)
        {
            if (_encryptionInfo == null && !string.IsNullOrEmpty(password)) return false;
            if (_encryptionInfo == null && string.IsNullOrEmpty(password)) return true;
            if (_encryptionInfo != null && string.IsNullOrEmpty(password)) return false;
            
            switch (_pFlag)
            {
                case ProtectionFlag.LegacyRC4: // works for office97/2000 word
                    RC4EncryptionHeader verifier = (RC4EncryptionHeader)_encryptionInfo;
                    return verifier.VerifyPassword(password);

                case ProtectionFlag.CapiRC4: // office2002/2003 word, need test
                    RC4EncryptionCryptoAPIHeader v2 = (RC4EncryptionCryptoAPIHeader)_encryptionInfo;
                    return v2.VerifyPassword(password);

                case ProtectionFlag.Standard: // works for office2007 word
                    StandardEncryptionHeader v3 = (StandardEncryptionHeader)_encryptionInfo;
                    byte[] key;
                    return v3.VerifyPassword(password, out key);

                case ProtectionFlag.Agile: // agile 2010 word, need test
                    AgileEncryptionHeader v4 = (AgileEncryptionHeader)_encryptionInfo;
                    return v4.VerifyPassword(password);

                case ProtectionFlag.Obfuscation:
                    return false; // not yet supported
                
                case ProtectionFlag.Protected:
                    return false;

                case ProtectionFlag.None:
                    return string.IsNullOrEmpty(password);

                case ProtectionFlag.Unknown:
                default:
                    return false;
            }
        }


        public string GetEncryptionInfo()
        {
            string disp;
            switch (_pFlag)
            {
                case ProtectionFlag.None:
                    disp = "\nNone";
                    break;

                case ProtectionFlag.Protected:
                    disp = "\nProtected with unknown algorithm";
                    break;

                case ProtectionFlag.Standard:
                    StandardEncryptionHeader s = (StandardEncryptionHeader)_encryptionInfo;
                    disp = "\nStandardEncryption" + (s!=null? s.ToDisplayString():"");
                    break;
                case ProtectionFlag.LegacyRC4:
                    RC4EncryptionHeader b = (RC4EncryptionHeader)_encryptionInfo;
                    disp= "\nRC4Encryption" + (b!=null? b.ToDisplayString():"");
                    break;

                case ProtectionFlag.CapiRC4:
                    RC4EncryptionCryptoAPIHeader c = (RC4EncryptionCryptoAPIHeader)_encryptionInfo;
                    disp = "\nRC4CryptoAPIEncryption" + (c!=null?c.ToDisplayString():"");
                    break;

                case ProtectionFlag.Agile:
                    AgileEncryptionHeader a = (AgileEncryptionHeader)_encryptionInfo;
                    disp= "\nAgileEncryption" + (a!=null?a.ToDisplayString():"");
                    break;

                case ProtectionFlag.Unknown:
                default:
                    disp = "\nUnknown";
                    break;
            }

            return disp;
        }



        // a general parse on file (encryption) information, no verification, no decryption
        public bool Read(string filename)
        {
            if (!IsMyFile(filename))
            {
                _lasterror = OfficeCryptErrors.FileFormatIncorrect;
                return false;
            }

            if (!File.Exists(filename))
            {
                _lasterror = OfficeCryptErrors.FileNotFound;
                return false;
            }

            // Read the file content
            this._filename = filename;
            this._contents = FileUtils.ReadAllBytes(filename);
            if (this._contents == null)
            {
                _lasterror = OfficeCryptErrors.FileFormatIncorrect;
                return false;
            }

            // get encryption information by parsing file streams
            ParseEncryptionInfo();
            return true;
        }


        private static bool IsMyFile(string filename)
        {
            FileInfo fi = new FileInfo(filename);
            if (!fi.Exists) return false;

            if (   fi.Extension != OfficeFileExtension.DOC && fi.Extension != OfficeFileExtension.DOCX      // how about .mdb
                && fi.Extension != OfficeFileExtension.XLS && fi.Extension != OfficeFileExtension.XLSX && fi.Extension != OfficeFileExtension.XLSB
                && fi.Extension != OfficeFileExtension.PPT && fi.Extension != OfficeFileExtension.PPTX
                )
                return false;

            return true;
        }



        // Note: file extension information assists the file type identification
        private void ParseEncryptionInfo()
        {
            FileInfo fi = new FileInfo(_filename);
            if (!fi.Exists)
            {
                _pFlag = ProtectionFlag.Unknown;
                _encryptionInfo = null;
                return;
            }

            // check file extension name
            if (   fi.Extension != OfficeFileExtension.DOC && fi.Extension != OfficeFileExtension.DOCX      // how about .mdb
                && fi.Extension != OfficeFileExtension.XLS && fi.Extension != OfficeFileExtension.XLSX && fi.Extension != OfficeFileExtension.XLSB
                && fi.Extension != OfficeFileExtension.PPT && fi.Extension != OfficeFileExtension.PPTX
                )
            {
                _pFlag = ProtectionFlag.Unknown;
                _encryptionInfo = null;
                return;
            }
            
            if (_contents == null)
            {
                _pFlag = ProtectionFlag.Unknown;
                _encryptionInfo = null;
                return;
            }

            // check file header
            try
            {
                // for office 2007 or 2010
                if (fi.Extension == OfficeFileExtension.DOCX ||  fi.Extension == OfficeFileExtension.XLSX || fi.Extension == OfficeFileExtension.PPTX
                    || fi.Extension == OfficeFileExtension.XLSB)
                {
                    // quick check on file header
                    bool bContainZipHeader = ContainsHeader(FileHeaderZip);
                    if (bContainZipHeader)  // zip package for plain file
                    {
                        _pFlag = ProtectionFlag.None;
                        _encryptionInfo = null;
                        return;
                    }

                    // otherwise would be OLE header for encrypted file
                    bool bContainOLEHeader = ContainsHeader(FileHeaderOLE);
                    if (!bContainOLEHeader)
                    {
                        _pFlag = ProtectionFlag.Unknown;  // not supported
                        _encryptionInfo = null;
                        return;
                    }

                    // create an OLE object
                    OleStorage storage = new OleStorage(_contents); // or _filename

                    // check stream
                    byte[] encryptionInfo = storage.ReadStream(StreamNames.csEncryptionInfoStreamName);
                    if (encryptionInfo != null)  // is Office2007 and above, and encrypted
                    {
                        // parse encryptionInfo
                        StandardEncryptionHeader s = StandardEncryption.ParseEncryptionInfoFromBytes(encryptionInfo);
                        if (s != null)
                        {
                            _pFlag = ProtectionFlag.Standard;
                            _encryptionInfo = s;
                            return;
                        }

                        AgileEncryptionHeader a = AgileEncryption.ParseEncryptionInfoFromBytes(encryptionInfo);
                        if (a != null)
                        {
                            _pFlag = ProtectionFlag.Agile;
                            _encryptionInfo = a;
                            return;
                        }

                        _pFlag = ProtectionFlag.Protected;
                        _encryptionInfo = null;  // however, we don't know encryption detail
                        return;
                    }
                    else
                    {
                        _pFlag = ProtectionFlag.None;
                        _encryptionInfo = null;
                        return;
                    }
                }
                // for office 97-2003
                else if (fi.Extension == OfficeFileExtension.DOC)
                {
                    // check OLE stream
                    RC4EncryptionHeader b = WordParser.ReadWordHeader_legacy(_contents);
                    if (b != null)
                    {
                        _pFlag = ProtectionFlag.LegacyRC4;
                        _encryptionInfo = b;
                        return;
                    }

                    RC4EncryptionCryptoAPIHeader c = WordParser.ReadWordHeader_capi(_contents);
                    if (c != null)
                    {
                        _pFlag = ProtectionFlag.CapiRC4;
                        _encryptionInfo = c;
                        return;
                    }

                    _pFlag = ProtectionFlag.None;
                    _encryptionInfo = null;
                    return;
                }
                // office 97-2003 excel is a slightly different
                else if (fi.Extension == OfficeFileExtension.XLS)
                {
                    IVerifier b = ExcelParser.ReadExcelHeader(_contents);
                    if (b != null)
                    {
                        if ( b is RC4EncryptionHeader)
                        {
                            _pFlag = ProtectionFlag.LegacyRC4;
                        }
                        else if (b is RC4EncryptionCryptoAPIHeader)
                        {
                            _pFlag = ProtectionFlag.CapiRC4;
                        }
                        else
                        {
                            _pFlag = ProtectionFlag.Obfuscation;  // TODO: not yet supported
                        }

                        _encryptionInfo = b;
                        return;
                    }

                    _pFlag = ProtectionFlag.None;
                    _encryptionInfo = null;
                    return;
                }
                // office 97-2003 ppt is a slightly different
                else if (fi.Extension == OfficeFileExtension.PPT)
                {
                    RC4EncryptionCryptoAPIHeader c = PowerPointParser.ReadPPTHeader(_contents);
                    if (c != null)
                    {
                        _pFlag = ProtectionFlag.CapiRC4;
                        _encryptionInfo = c; 
                        return;
                    }
                    else
                    {
                        _pFlag = ProtectionFlag.None;
                        _encryptionInfo = null;
                        return;
                    }
                }

                _pFlag = ProtectionFlag.Unknown;
                _encryptionInfo = null;
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                _pFlag = ProtectionFlag.None; // temp because NPOI v1.2.5 cannot handle plain office 2007 stream
                _encryptionInfo = null;
                return;  
            }
        }



        // Checks the header without messing up the stream
        private bool ContainsHeader(byte[] header)
        {
            try
            {
                for (int i = 0; i < header.Length; i++)
                {
                    if (_contents[i] != header[i]) return false;
                }

                return true;
            }
            catch (Exception)
            {
                return false;  // caused by short length of _contents
            }
        }





    }
}

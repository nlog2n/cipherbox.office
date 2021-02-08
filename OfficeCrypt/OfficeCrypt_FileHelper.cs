using System;
using System.IO;
using System.Collections;

namespace CipherBox.Office
{
    public interface IFileLocker
    {
        #region for instance
        string Password { get; set; }  // change password
        byte[] Open(string filename, string password); // open document, internally decryption if password-protected
        bool Save(); // save encrypted or decrypted, determined by password setting. open + save will do on file
        bool SaveAs(string filename); // save to another file name
        string GetEncryptionInfo();   // display
        bool Read(string filename);   // general read without verification or decryption
        bool Verify(string password); // read + verify will do on file
        #endregion
    }


    public interface ILocker
    {
        #region for static functions
        bool IsMyFile(string filepath);
        bool IsProtected(string filepath);
        bool AddPassword(string filepath, string password);
        bool RemovePassword(string filepath, string password);
        void ChangePassword(string filepath, string oldPassword, string newPassword);
        bool VerifyPassword(string filepath, string password);
        string GetEncryptionInfo(string filepath);
        #endregion
    }




	/// <summary>
	/// password add and remove
	/// </summary>
	public static class OfficeHelper
	{
        // API function
        public static bool IsMyFile(string filename)
        {
            try
            {
                IFileLocker s = new OfficeCryptStream();
                if (!s.Read(filename))
                    return false; // fail

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        // API function
        public static bool IsProtected(string filename)
        {
            try
            {
                OfficeCryptStream s = new OfficeCryptStream();
                if (!s.Read(filename))
                    return false; // fail

                ProtectionFlag result = s._pFlag;
                return (result == ProtectionFlag.Protected || result == ProtectionFlag.LegacyRC4 || result == ProtectionFlag.CapiRC4 ||
                    result == ProtectionFlag.Standard || result == ProtectionFlag.Agile);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        public static string GetEncryptionInfo(string filename)
        {
            try
            {
                IFileLocker s = new OfficeCryptStream();
                if (!s.Read(filename))
                    return "\nN/A"; // fail

                return s.GetEncryptionInfo();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "\nN/A";
            }
        }


        // API function
        public static bool AddPassword(string TestFile, string password)
        {
            return ChangePassword(TestFile, null, password);
        }

        // API function
        public static bool RemovePassword(string TestFile, string password)
        {
            return ChangePassword(TestFile, password, null);
        }


        // 1. "a"  => "b"  change password
        // 2. null => "b"  add password
        // 3. "a"  => null remove password
        public static bool ChangePassword(string filename, String oldPassword, String newPassword)
        {
            try
            {
                // open with old password
                IFileLocker s = new OfficeCryptStream();
                if ( s.Open(filename, oldPassword) == null)
                    return false; // fail

                // reset password
                s.Password = newPassword;

                // save and close
                return s.Save();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        public static bool VerifyPassword(string filename, String password)
        {
            try
            {
                IFileLocker s = new OfficeCryptStream();
                if (!s.Read(filename))
                    return false; // fail

                return s.Verify(password);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        
	}
}

/*
 *  test password verification, stream read/write
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

using CipherBox.PasswordGeneration;
using CipherBox.Office;   // office 97/2000, 2002/2003, 2007, 2010

namespace CipherBox.Office.Test
{
    partial class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Help:");
                Console.WriteLine(" program show   wordfile          - show enc info");
                Console.WriteLine(" program ole    olefile           - show ole tree");
                Console.WriteLine(" program verify wordfile password - verify password");
                Console.WriteLine(" program lock   wordfile password - lock file");
                Console.WriteLine(" program unlock wordfile password - unlock file");
                Console.WriteLine(" program crack  wordfile passw**d - by brute-force");
                Console.WriteLine(" program search wordfile passbook - by dictionary");
                return;
            }

            string cmd = "show";
            string filename = "test.xlsx";
            string passbook = "passbook.txt";
            string password = "password";
            if (args.Length > 0) { cmd = args[0]; }
            if (args.Length > 1) { filename = args[1]; }
            if (args.Length > 2) { passbook = args[2]; password = args[2]; }


            if (args.Length == 2 && cmd == "show")
            {
                string dis = OfficeHelper.GetEncryptionInfo(filename);
                Console.WriteLine(dis);
                return;
            }

            if (args.Length == 2 && cmd == "ole")
            {
                OLE.OleStorage storage = new OLE.OleStorage(filename);
                storage.PrintStorage();
                return;
            }

            if (args.Length == 3 && cmd == "verify")
            {
                if (OfficeHelper.VerifyPassword(filename, password))
                {
                    Console.WriteLine("success");                    
                }
                else
                {
                    Console.WriteLine("fail");
                }
                return;
            }

            if (args.Length == 3 && cmd == "lock")
            {
                if (OfficeHelper.AddPassword(filename, password))
                {
                    Console.WriteLine("success");
                }
                else
                {
                    Console.WriteLine("fail");
                }
            }

            if (args.Length == 3 && cmd == "unlock")
            {
                if (OfficeHelper.RemovePassword(filename, password))
                {
                    Console.WriteLine("success");
                }
                else
                {
                    Console.WriteLine("fail");
                }
            }


            if (args.Length == 3 && cmd == "crack")
            {
                brute_force(filename, password);
            }


            if (args.Length == 3 && cmd == "search")
            {
                search_dictionary(filename, passbook);
            }
        }


    }
}

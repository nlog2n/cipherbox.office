/*
 *  test office password verification 
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
        static string display_time(decimal miliseconds)
        {
            decimal t = miliseconds;

            if (t < 1000) return t.ToString("0.") + "ms";

            if (t/1000 < 60) return (t / 1000).ToString("0.") + "s";

            if (t/1000/60 < 60) return (t / 1000 / 60).ToString("0.") + "min";

            if (t/1000/60/60 < 24) return (t / 1000 / 60 / 60).ToString("0.") + "h";

            if (t/1000/60/60/24 < 365) return (t / 1000 / 60 / 60 / 24).ToString("0.") + "d";

            return (t/1000/60/60/24/365).ToString("0.") + "y";
        }

        // try all possible combinations of password
        static void brute_force(string wordfile, string passmask)
        {
            IFileLocker f = new OfficeCryptStream();
            if (!f.Read(wordfile))
            {
                Console.WriteLine("read office file error");
                return; // fail
            }

            if (f.Verify(passmask))
            {
                Console.WriteLine("\nPassword=" + passmask);
                return;
            }

            PasswordGenerator pwdGenerator = new PasswordGenerator(passmask);
            pwdGenerator.IncludeChars = true;
            pwdGenerator.IncludeDigits = true;

            decimal startIndex = pwdGenerator.StartIndex(); // can be 0 simply
            decimal endIndex = pwdGenerator.EndIndex();
            long t1 = Environment.TickCount;
            for (decimal counter = startIndex; counter < endIndex; counter++)
            {
                string password = pwdGenerator.Password(counter);

                bool verifed = f.Verify(password);

                long t2 = Environment.TickCount;
                decimal costtime = (t2 - t1);  // in miliseconds
                decimal avgspeed = (costtime == 0 ? 0 : (counter +1 - startIndex) * 1000 / costtime);  // counter/second
                decimal percent =  (counter == endIndex -1 ? 1:(counter +1 - startIndex) / (endIndex - startIndex));
                decimal remainedtime = (counter == endIndex -1 ? 0 : (endIndex - counter) * (t2 - t1) / (counter +1 - startIndex)); // in miliseconds
                Console.Write("\r" + password + "\t" + percent.ToString("P2") + "\tpps=" + avgspeed.ToString("0.") + "\telapse=" + display_time(costtime) + "\tremain=" + display_time(remainedtime) + "\t");

                if (verifed)
                {
                    Console.WriteLine("\nPassword=" + password);
                    return;
                }
            }
            Console.WriteLine("\nFailed");
        }

        // input: passbook file, one password for each line
        static void search_dictionary(string wordfile, string passbook)
        {
            decimal counter = 0;
            string line;

            IFileLocker f = new OfficeCryptStream();
            if (!f.Read(wordfile))
            {
                Console.WriteLine("read office file error");
                return; // fail
            }


            // Read the password file and display it line by line.
            System.IO.StreamReader file = new System.IO.StreamReader(passbook);
            while ((line = file.ReadLine()) != null)
            {
                if (f.Verify(line))
                {
                    Console.WriteLine("\nPassword=" + line);
                    return;
                }
                else
                {
                    Console.Write("\r" + line + "\t\t" + counter.ToString());
                }
                
                counter++;
            }

            file.Close();

            // Suspend the screen.
            //Console.ReadLine();
        }




    }
}

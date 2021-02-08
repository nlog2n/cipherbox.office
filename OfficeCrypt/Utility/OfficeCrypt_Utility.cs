// utility functions for 2007 and agile encryption for office 2010

using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;

//using System.IO.Packaging;  // need Net 3.0 and refer to WindowsBase.dll, used by CreatePackage() below


namespace CipherBox.Office.Utility
{

    // used by Agile2010.cs
    public static class XmlExtension
    {
        public static string ValueOrDefault(this XAttribute attr, string defaultValue)
        {
            if (attr == null) return defaultValue;
            return attr.Value;
        }

        public static int ToInt(this XAttribute attr, int defaultValue)
        {
            if (attr == null) return defaultValue;
            int result = defaultValue;
            int.TryParse(attr.Value, out result);
            return result;
        }
    }

    public class PackageExtension
    {
        // byte array  to stream
        public static System.IO.MemoryStream CreateStream(byte[] decryptedPackage)
        {
            System.IO.MemoryStream ms = new System.IO.MemoryStream();

            if (decryptedPackage != null) 
            {
                ms.Write(decryptedPackage, 0, decryptedPackage.Length);
                ms.Flush();
                ms.Position = 0;
            }

            return ms;
        }


        // byte array to System.IO.Packaging.Package, which provides access to plaintext Office 2007 Open XML file (ZIP format)
        /*
        public static Package CreatePackage(byte[] decryptedPackage)
        {
            if (decryptedPackage == null) return null; 

            using (System.IO.MemoryStream ms = CreateStream(decryptedPackage))
            {
                return Package.Open(ms, System.IO.FileMode.Open, System.IO.FileAccess.ReadWrite);
            }
        }
        */
    }


    public static class FileUtils
    {
        //  file to bytes
        //    byte[] contents = File.ReadAllBytes(@"C:\temp\mww_plain.xlsx");
        //    File.WriteAllBytes(@"C:\temp\z_decrypted.xlsx", contents);

        public static byte[] ReadAllBytes(string filename)
        {
            // The File.ReadAllBytes() suffers two problems:
            // 1. can only read at most 2GB at once
            // 2. default FileShare.Read setting may still cause IO exception when other process uses the same file
            // http://blog.somecreativity.com/2008/04/04/ioexception-when-trying-to-read-a-file-using-filereadallbytes-function/
            // so turn to use FileStream with FileShare.ReadWrite
            byte[] bytes = null;
            using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                int index = 0;
                long fileLength = fs.Length;
                if (fileLength > Int32.MaxValue)
                {
                    //throw new IOException("File too long");
                    Console.WriteLine("File too long:" + filename);
                    return null;
                }
                int count = (int)fileLength;
                bytes = new byte[count];
                while (count > 0)
                {
                    int n = fs.Read(bytes, index, count);
                    if (n == 0)
                    {
                        //throw new InvalidOperationException("End of file reached before expected");
                        Console.WriteLine("End of file reached before expected:" + filename);
                        return null;
                    }
                    index += n;
                    count -= n;
                }
            }
            return bytes;
        }

        public static void WriteAllBytes(string filename, byte[] bytes)
        {
            // Sometimes the file is read-only. Do I need to enable writing?
            // refer to: http://stackoverflow.com/questions/1202022/best-way-to-make-a-file-writeable-in-c-sharp
            bool ronly = false;
            FileAttributes attributes = File.GetAttributes(filename);
            if ((attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
            {
                Console.WriteLine("read-only file");
                ronly = true;

                // remove the read-only flag
                File.SetAttributes(filename, attributes & ~FileAttributes.ReadOnly);
            }

            // write bytes to file
            File.WriteAllBytes(filename, bytes);

            // recover the read-only flag
            if (ronly)
            {
                File.SetAttributes(filename, attributes | FileAttributes.ReadOnly);
            }
        }

    }


    /// <summary>
    /// extension methods for stream
    /// </summary>
    public static class StreamUtils
    {
        // Read a given number of bytes and fail if not all present
        public static byte[] ReadBytes(Stream stream, int bytesToRead)
        {
            var buffer = new byte[bytesToRead];
            if (stream.Read(buffer, 0, buffer.Length) != bytesToRead)
                throw new InvalidDataException("Not enough stream data");

            return buffer;
        }

        // Read an Int16
        public static Int16 ReadInt16(this Stream stream)
        {
            return BitConverter.ToInt16(ReadBytes(stream, sizeof(Int16)), 0);
        }

        // Read an Int32
        public static Int32 ReadInt32(this Stream stream)
        {
            return BitConverter.ToInt32(ReadBytes(stream, sizeof(Int32)), 0);
        }
        
        // Read an Int64
        public static Int64 ReadInt64(this Stream stream)
        {
            return BitConverter.ToInt64(ReadBytes(stream, sizeof(Int64)), 0);
        }

        // Write an Int16
        public static void WriteInt16(this Stream stream, Int16 value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, sizeof(Int16));
        }

        // Write an Int32
        public static void WriteInt32(this Stream stream, Int32 value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, sizeof(Int32));
        }

        // Write an Int64
        public static void WriteInt64(this Stream stream, Int64 value)
        {
            stream.Write(BitConverter.GetBytes(value), 0, sizeof(Int64));
        }

    }


}

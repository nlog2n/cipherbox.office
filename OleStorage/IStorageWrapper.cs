// parse office document for OLE storage streams
// to provide uniform API functions to upper layer:
//  
//  * Constructors, SaveAs(file), GetAllBytes
//  * ReadStrem(name), WriteStream(name)
//  * ListStreams()

using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace CipherBox.Office.OLE
{
    public interface IStorageWrapper
    {
        // input only
        // Constructor();
        // Constructor( string filename);
        // Constructor( byte[] filecontents);

        List<string> ListStreams();
        List<string> ListStreams(IStorage currentStorage);

        bool FoundStream(string streamName);
        bool FoundStream(IStorage currentStorage, string streamName);

        byte[] ReadStream(string streamName); // read an existing stream under root
        byte[] ReadStream(IStorage currentStorage, string streamName); // read an existing stream under specified storage

        void WriteStream(string streamName, byte[] contents);  // write/create stream under root
        void WriteStream(IStorage currentStorage, string streamName, byte[] streamData); // write/create a stream under specified storage

        // note: remember to Marshal.ReleaseComObject(result) after use
        IStorage OpenStorage(string storageName); // open an existing sub-storage under root
        IStorage OpenStorage(IStorage parentStorage, string storageName); // open an existing sub-storage under specified parent

        // note: remember to Marshal.ReleaseComObject(result) after use
        IStorage CreateStorage(string subStorageName); // create a sub storage under root
        IStorage CreateStorage(IStorage currentStorage, string subStorageName); // create a sub storage under specified storage

        void Remove(string pwcsName); // remove stream or substorage
        void Remove(IStorage storage, string pwcsName);

        // output functions
        byte[] GetAllBytes();
        void SaveAs(string filename);

        // print
        void PrintStorage(); // enumerate storage tree and print
        void PrintStorage(IStorage storage, int level);
    }
}

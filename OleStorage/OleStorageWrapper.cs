using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices;

// Visual Studio project build setting: allow unsafe code (because of address reference)

namespace CipherBox.Office.OLE
{
    /// <summary>
    /// P/Invoke for OLE storages
    /// unmanaged resource like IStorage object needs clean-up upon close
    /// </summary>
    public class OleStorage: IDisposable, IStorageWrapper
    {
        #region OLE enumerations
        [Flags]
        public enum STGM : uint
        {
            DIRECT = 0x00000000,
            TRANSACTED = 0x00010000,
            SIMPLE = 0x08000000,
            READ = 0x00000000,
            WRITE = 0x00000001,
            READWRITE = 0x00000002,
            SHARE_DENY_NONE = 0x00000040,
            SHARE_DENY_READ = 0x00000030,
            SHARE_DENY_WRITE = 0x00000020,
            SHARE_EXCLUSIVE = 0x00000010,
            PRIORITY = 0x00040000,
            DELETEONRELEASE = 0x04000000,
            NOSCRATCH = 0x00100000,
            CREATE = 0x00001000,
            CONVERT = 0x00020000,
            FAILIFTHERE = 0x00000000,
            NOSNAPSHOT = 0x00200000,
            DIRECT_SWMR = 0x00400000,

            ReadOnly = STGM.DIRECT | STGM.READ | STGM.SHARE_EXCLUSIVE,
            ReadWrite = STGM.DIRECT | STGM.READWRITE | STGM.SHARE_EXCLUSIVE,
            Create = STGM.CREATE | STGM.ReadWrite,
        }

        public enum STATFLAG : uint
        {
            STATFLAG_DEFAULT = 0,
            STATFLAG_NONAME = 1,
            STATFLAG_NOOPEN = 2
        }

        public enum STGFMT : uint
        {
            STGFMT_STORAGE = 0,
            STGFMT_FILE = 3,
            STGFMT_ANY = 4,
            STGFMT_DOCFILE = 5
        }
        #endregion

        #region Import Ole32.dll interfaces
        [DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StgIsStorageFile(string pwcsName);

        [DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StgIsStorageILockBytes(ILockBytes plkbyt);
        
        [DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
		private static extern uint StgOpenStorage(string pwcsName, IntPtr pstgPriority, STGM grfMode,  IntPtr snb, uint reserved, out IStorage pstorage);

        [DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StgOpenStorageOnILockBytes(ILockBytes plkbyt, IntPtr pstgPriority, STGM grfMode, IntPtr snbEnclude, uint reserved, out IStorage ppstgOpen);

		[DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StgCreateDocfile(string pwcsName, STGM grfMode, IntPtr reserved, out IStorage storage);

		[DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint CreateILockBytesOnHGlobal(IntPtr hGlobal, bool fDeleteOnRelease,  out ILockBytes ppLockbytes);

        [DllImport("OLE32.dll", CharSet = CharSet.Unicode)]
        private static extern uint StgCreateDocfileOnILockBytes(ILockBytes plkbyt, STGM grfMode, uint reserved, out IStorage ppstgOpen);
        #endregion

        #region private members
        private IStorage _storage = null;  // root storage
        private ILockBytes _lockbytes = null; // underlying buffer

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // clear managed resources
            }

            // clear unmanaged resources
            if (this._storage != null)
            {
                Marshal.ReleaseComObject(this._storage);
                this._storage = null;
            }
            if (this._lockbytes != null)
            {
                Marshal.ReleaseComObject(this._lockbytes);
                this._lockbytes = null;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~OleStorage()
        {
            Dispose(false);
        }

        #endregion

        #region constructors
        // Open an existing storage file for read/write
        // note: the modifications do not apply to file automatically
        public OleStorage(string filename)
        {
            //this._storage = OpenRootStorage(filename);
            byte[] filecontents = File.ReadAllBytes(filename);
            this._storage = CreateRootStorage(filecontents);
        }

        // open an existing storage stream for read/write
        public OleStorage(byte[] filecontents)
        {
            this._storage = CreateRootStorage(filecontents);
        }

        // create the document in-memory for write
        public OleStorage()
        {
            this._storage = CreateRootStorage(null);
            // now you can start to write stream...
        }

        // turn bytes into a ILockBytes object
        private static ILockBytes GetLockbytes(byte[] filecontents)
        {
            // create an ILockBytes object
            ILockBytes lockbytes;
            uint hresult = CreateILockBytesOnHGlobal(IntPtr.Zero, true, out lockbytes);
            if (hresult != 0) // not S_OK, in such case storage == null
            {
                Console.WriteLine("Failed to create ILockBytes for the storage " + hresult.ToString("X"));
                return null;
            }

            // write bytes to ILockBytes object
            if (filecontents != null)
            {
                // create unmanaged pointer to bytes
                IntPtr buffer = Marshal.AllocHGlobal(filecontents.Length);
                Marshal.Copy(filecontents, 0, buffer, filecontents.Length);

                // write to lockbytes
                UIntPtr writeSize;
                lockbytes.WriteAt(0, buffer, filecontents.Length, out writeSize);

                // free unmangaged buffer
                Marshal.FreeHGlobal(buffer);
            }

            return lockbytes;
        }

        // create root storage based on lock bytes
        private IStorage CreateRootStorage(byte[] filecontents)
        {
            // create an ILockBytes object based on bytes
            this._lockbytes = GetLockbytes(filecontents);
            if (this._lockbytes == null) return null;

            IStorage root = null;
            if (filecontents != null)  // open root storage 
            {
                if (StgIsStorageILockBytes(this._lockbytes) != 0)
                {
                    Console.WriteLine("Not an OLE storage bytes");
                    return null;
                }

                // create IStorage based on ILockBytes
                uint hresult = StgOpenStorageOnILockBytes(this._lockbytes, IntPtr.Zero, 
                    STGM.ReadWrite, // or STGM.ReadOnly
                    IntPtr.Zero, 0, out root);
                if (hresult != 0) // not S_OK, in such case storage == null
                {
                    Console.WriteLine("Failed to open the storage " + hresult.ToString("X"));
                    return null;
                }
            }
            else  // create a new root storage
            {
                // create IStorage based on ILockBytes
                uint hresult = StgCreateDocfileOnILockBytes(this._lockbytes,
                    STGM.Create, // STGM.DIRECT: changes commit immediately, while STGM.TRANSACTED needs explicit commit
                    0,
                    out root);
                if (hresult != 0) // not S_OK, in such case storage == null
                {
                    Console.WriteLine("Failed to create storage " + hresult.ToString("X"));
                    return null;
                }
            }

            return root;
        }

        // Func: open a storage file. if file does not exist, create a new one for write
        // Note: this function does not use underlying lockbytes, which means u cannot call GetAllBytes() directly
        // Reserved for private
        private IStorage OpenRootStorage(string filename)
        {
            IStorage root;
            if (File.Exists(filename))
            {
                // check if it is OLE format
                if (StgIsStorageFile(filename) != 0)
                {
                    Console.WriteLine("Not an OLE storage file: " + filename);
                    return null;
                }

                // open file in read/write mode
                uint hresult = StgOpenStorage(filename, IntPtr.Zero, STGM.ReadWrite, IntPtr.Zero, 0, out root);
                if (hresult != 0) // not S_OK, in such case storage == null
                {
                    Console.WriteLine("Failed to open the storage " + hresult.ToString("X"));
                    return null;
                }
            }
            else
            {
                // Create a new storage for given filename
                uint hresult = StgCreateDocfile(filename, STGM.Create, IntPtr.Zero, out root);
                if (hresult != 0) // in such case storage == null
                {
                    Console.WriteLine("Failed to create the storage for file " + filename);
                    return null;
                }

                // now you can start to write stream...
            }

            return root;
        }

        #endregion

        #region save operations

        // get bytes for whole storage stream
        // note: !!so far only support storage created based on lockbytes, for example, OleStorage()
        // one work-around: create a new IStorage object based on lockbytes, CopyTo, then get bytes from new one.
        public byte[] GetAllBytes()
        {
            //PrintStorage();

            if (this._lockbytes == null) return null;
            this._lockbytes.Flush();

            // read lockbytes to buffer
            System.Runtime.InteropServices.ComTypes.STATSTG statstg;
            this._lockbytes.Stat(out statstg, 0);
            int size = (int)statstg.cbSize;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            UIntPtr readSize;
            this._lockbytes.ReadAt(0, buffer, size, out readSize);

            // copy buffer to byte array
            byte[] bytes = new byte[size];
            Marshal.Copy(buffer, bytes, 0, size);
            Marshal.FreeHGlobal(buffer);

            return bytes;
        }


        public void SaveAs(string filename)
        {
            byte[] bytes = GetAllBytes();
            if (bytes != null)
            {
                File.WriteAllBytes(filename, bytes);
            }
            else
            {
                Console.WriteLine("warning: null storage stream, not saved.");
            }
        }

        #endregion

        #region read stream functions

        public byte[] ReadStream(string streamName)
        {
            return ReadStream(this._storage, streamName);
        }
        
        // Open an existing stream for read only
        // note: stream must be exactly under this storage
        public byte[] ReadStream(IStorage currentStorage, string streamName)
        {
            if (currentStorage == null) return null;

            try
            {
                IStream istream;
                currentStorage.OpenStream(streamName, IntPtr.Zero, (uint)STGM.ReadOnly, 0, out istream);

                System.Runtime.InteropServices.ComTypes.STATSTG statstg;
                istream.Stat(out statstg, (int)STATFLAG.STATFLAG_NONAME);

                byte[] data = new byte[statstg.cbSize];
                istream.Read(data, (int)statstg.cbSize, IntPtr.Zero);
                Marshal.ReleaseComObject(istream);

                return data;
            }
            catch (Exception ex)
            {
                Console.WriteLine("warning: read " + streamName + " stream error, " +ex.Message);
                return null;
            }
        }


        public bool FoundStream(string streamName)
        {
            return FoundStream(this._storage, streamName);
        }


        // enumerate all streams and return the matched one
        // note: search only streams under current storage level
        // refer to: excel2folder.encryptedpackagehandler.cs => GetStreamFromPackage
        //           excel2folder.encryptedpackagehandler.cs =>GetOleStream
        public bool FoundStream(IStorage currentStorage, string streamName)
        {
            bool found = false;

            System.Runtime.InteropServices.ComTypes.STATSTG statstg;
            currentStorage.Stat(out statstg, (uint)STATFLAG.STATFLAG_DEFAULT);

            IEnumSTATSTG pIEnumStatStg = null;
            currentStorage.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);

            System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = { statstg };
            uint fetched = 0;
            uint hresult = 0;
            while (true)
            {
                if (statstg.type == 2 && statstg.pwcsName == streamName)
                {
                    found = true; // ReadStream(storage, streamName);
                    break; // note: need to release marshal object
                }

                hresult = pIEnumStatStg.Next(1, regelt, out fetched);
                if (hresult != 0) break;

                statstg = regelt[0];
            }

            Marshal.ReleaseComObject(pIEnumStatStg);
            return found;
        }


        public List<string> ListStreams()
        {
            return ListStreams(this._storage);
        }

        public List<string> ListStreams(IStorage currentStorage)
        {
            List<string> result = new List<string>();

            System.Runtime.InteropServices.ComTypes.STATSTG statstg;
            currentStorage.Stat(out statstg, (uint)STATFLAG.STATFLAG_DEFAULT);

            IEnumSTATSTG pIEnumStatStg = null;
            currentStorage.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);

            System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = { statstg };
            uint fetched = 0;
            uint hresult = 0;
            while (true)
            {
                if (statstg.type == 2)
                {
                    result.Add(statstg.pwcsName);
                }

                hresult = pIEnumStatStg.Next(1, regelt, out fetched);
                if (hresult != 0) break;

                statstg = regelt[0];
            }

            Marshal.ReleaseComObject(pIEnumStatStg);
            return result;
        }
        
        #endregion

        #region write stream functions

        public void WriteStream(string streamName, byte[] streamData)
        {
            WriteStream(this._storage, streamName, streamData);
        }

        // write/create a stream under specified storage
        public void WriteStream(IStorage currentStorage, string streamName, byte[] streamData)
        {
            if (currentStorage == null) return;

            if (FoundStream(currentStorage, streamName))  // already exists
            {
                // Open an existing stream for read/write
                IStream istream;
                currentStorage.OpenStream(streamName, IntPtr.Zero, (uint)STGM.ReadWrite, 0, out istream);
                if (istream == null)
                {
                    Console.WriteLine("Failed to open the stream for write: " + streamName);
                    return;
                }

                istream.Seek(0 /*offsetFromOrigin*/, 0 /*STREAM_SEEK_SET*/, IntPtr.Zero);
                istream.Write(streamData, streamData.Length, IntPtr.Zero);
                istream.SetSize(streamData.Length);
                istream.Commit(0);

                Marshal.ReleaseComObject(istream);
            }
            else
            {
                // write as a new stream
                IStream istream;
                currentStorage.CreateStream(streamName, (uint)STGM.Create, 0, 0, out istream);
                if (istream == null)
                {
                    Console.WriteLine("Failed to create the stream: " + streamName);
                    return;
                }

                istream.Write(streamData, streamData.Length, IntPtr.Zero);
                istream.Commit(0);

                Marshal.ReleaseComObject(istream);
            }

            currentStorage.Commit(0);
        }

        #endregion

        #region storage node operations
        // open an existing sub-storage under root
        public IStorage OpenStorage(string storageName)
        {
            return OpenStorage(this._storage, storageName);
        }

        // open an existing sub-storage under specified parent
        public IStorage OpenStorage(IStorage parentStorage, string storageName)
        {
            if (parentStorage == null) return null;

            try
            {
                IStorage childStorage;
                parentStorage.OpenStorage(storageName,
                    null,
                    (uint)STGM.ReadWrite, // (uint)STGM.ReadOnly,
                    IntPtr.Zero,
                    0,
                    out childStorage);

                return childStorage;
            }
            catch (Exception)
            {
                Console.WriteLine("failure on open storage " + storageName);
                return null;
            }
        }

        // create a sub storage under root
        // note: remember to Marshal.ReleaseComObject(result) after use
        public IStorage CreateStorage(string subStorageName)
        {
            return CreateStorage(this._storage, subStorageName);
        }

        // create a sub storage under specified storage
        // note: remember to Marshal.ReleaseComObject(result) after use
        public IStorage CreateStorage(IStorage currentStorage, string subStorageName)
        {
            IStorage subStorage;
            currentStorage.CreateStorage( subStorageName,
                (uint)STGM.Create,
                0, 0, out subStorage);
            currentStorage.Commit(0);
            return subStorage;
        }
        #endregion

        #region print helper
        private string MapNameToPrintableName(string stgName)
        {
            if (string.IsNullOrEmpty(stgName)) return stgName;

            if (stgName[0] < ' ')  // first character is special (0x00-0x1f)
            {
                byte ch = (byte)stgName[0]; 
                stgName = stgName.Substring(1, stgName.Length - 1);
                stgName = "\\0x" + ch.ToString("x2") + stgName; 
            }
            return stgName;
        }

        public void PrintStorage()
        {
            PrintStorage(this._storage, 0);
        }

        // Help method to print a storage tree
        public void PrintStorage(IStorage storage, int level)
        {
            if (storage == null) return;

            // get storage stats
            System.Runtime.InteropServices.ComTypes.STATSTG statstg;
            storage.Stat(out statstg, (uint)STATFLAG.STATFLAG_DEFAULT);

            // create an enumeration for this storage
            IEnumSTATSTG pIEnumStatStg = null;
            System.Runtime.InteropServices.ComTypes.STATSTG[] regeltSub = { statstg };
            storage.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);

            uint fetched = 0;
            while (pIEnumStatStg.Next(1, regeltSub, out fetched) == 0)
            {
                //topName = MapNameToPrintableName(topName);
                string sName = MapNameToPrintableName(regeltSub[0].pwcsName);
                for (int i = 0; i < level; i++) { sName = '\t' + sName; }
                switch (regeltSub[0].type)
                {
                    case 1: // storage
                        Console.WriteLine(sName + ": storage");
                        IStorage nextStorage = OpenStorage(storage, regeltSub[0].pwcsName);
                        PrintStorage(nextStorage, level + 1);
                        Marshal.ReleaseComObject(nextStorage);
                        break;
                    case 2: // stream
                        Console.WriteLine(sName + ", " + ReadStream(storage, regeltSub[0].pwcsName).Length.ToString() + " bytes");
                        break;
                    default:
                        Console.WriteLine(sName + ": unexpected storage type");
                        break;
                }
            }

            Marshal.ReleaseComObject(pIEnumStatStg);
        }
        #endregion
        
        #region remove stream/storage operations

        // remove stream or substorage
        public void Remove(string pwcsName)
        {
            Remove(this._storage, pwcsName);
        }

        public void Remove(IStorage storage, string pwcsName)
        {
            storage.DestroyElement(pwcsName);
            storage.Commit(0);
        }

        #endregion


    }
}

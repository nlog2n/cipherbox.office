using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices;

namespace CipherBox.Office.OLE
{
    [ComVisible(false)]
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000000A-0000-0000-C000-000000000046")]
    public interface ILockBytes
    {
        void ReadAt(long ulOffset, System.IntPtr pv, int cb, out UIntPtr pcbRead);
        void WriteAt(long ulOffset, System.IntPtr pv, int cb, out UIntPtr pcbWritten);
        void Flush();
        void SetSize(long cb);
        void LockRegion(long libOffset, long cb, int dwLockType);
        void UnlockRegion(long libOffset, long cb, int dwLockType);
        void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg, int grfStatFlag);
    }
}

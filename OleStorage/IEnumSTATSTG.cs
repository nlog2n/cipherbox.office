using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices;

namespace CipherBox.Office.OLE
{
    [ComVisible(false)]
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000000D-0000-0000-C000-000000000046")]
    public interface IEnumSTATSTG
    {
        // The user needs to allocate an STATSTG array whose size is celt. 
        [PreserveSig]
        uint Next(
            uint celt,
            [MarshalAs(UnmanagedType.LPArray), Out] 
            System.Runtime.InteropServices.ComTypes.STATSTG[] rgelt,
            out uint pceltFetched
        );

        void Skip(uint celt);

        void Reset();

        [return: MarshalAs(UnmanagedType.Interface)]
        IEnumSTATSTG Clone();
    } 
}

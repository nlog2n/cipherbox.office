using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices;

namespace CipherBox.Office.OLE
{
    /*
    [ComVisible(false)]
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000000C-0000-0000-C000-000000000046")]
    public interface IStream
    {
        void Read(byte[] pv, int cb, IntPtr pcbRead);
        void Write(byte[] pv, int cb, IntPtr pcbWritten);
        void Seek(long dlibMove, int dwOrigin, IntPtr plibNewPosition);
        void Clone(out IStream ppstm);
        void Commit(int grfCommitFlags);
        void CopyTo(IStream pstm, long cb, IntPtr pcbRead, IntPtr pcbWritten);
        void Revert();
        void SetSize(long libNewSize);
        void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg, int grfStatFlag);
        void LockRegion(long libOffset, long cb, int dwLockType);
        void UnlockRegion(long libOffset, long cb, int dwLockType);
    }
    */





    /// <summary>
    /// Simple Stream wrapper over IStream, which is returned from IStorage PInvoke operations
    /// </summary>
    public class StreamOnIStream : Stream
    {
        private IStream istream;
        private byte[] tempBuffer = new byte[64 * 1024];

        public StreamOnIStream(IStream istream)
        {
            this.istream = istream;
        }

        ~StreamOnIStream()
        {
            Dispose(false /*disposing*/);
        }

        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return true; } }

        public override long Length
        {
            get
            {
                System.Runtime.InteropServices.ComTypes.STATSTG stats;
                this.istream.Stat(out stats, 1 /*STATFLAG_NONAME*/);
                return stats.cbSize;
            }
        }

        public unsafe override long Position
        {
            get
            {
                ulong newPosition;
                IntPtr newPositionPointer = new IntPtr(&newPosition);
                this.istream.Seek(0 /*offsetFromOrigin*/, 1 /*STREAM_SEEK_CUR*/, newPositionPointer);
                return (long)newPosition;
            }
            set
            {
                this.istream.Seek(value, 0 /*STREAM_SEEK_SET*/, IntPtr.Zero);
            }
        }

        public override void Flush()
        {
            this.istream.Commit(0 /*STGC_DEFAULT*/);
        }

        public unsafe override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset");
            }

            if ((buffer.Length - offset) < count)
            {
                throw new ArgumentException("offset + count > buffer.Length");
            }

            ulong bytesRead;
            IntPtr bytesReadPointer = new IntPtr(&bytesRead);
            int totalBytesRead = 0;

            if (offset == 0)
            {
                this.istream.Read(buffer, count, bytesReadPointer);
                totalBytesRead = (int)bytesRead;
            }
            else
            {
                int bytesRemaining = count;
                while (bytesRemaining > 0)
                {
                    int bytesToRead = Math.Min(bytesRemaining, this.tempBuffer.Length);
                    this.istream.Read(this.tempBuffer, bytesToRead, bytesReadPointer);
                    Buffer.BlockCopy(this.tempBuffer, 0, buffer, offset, (int)bytesRead);

                    bytesRemaining -= (int)bytesRead;
                    offset += (int)bytesRead;
                    totalBytesRead += (int)bytesRead;
                    if (bytesRead == 0)
                    {
                        bytesRemaining = 0;
                    }
                }
            }

            return totalBytesRead;
        }

        public unsafe override long Seek(long offset, SeekOrigin origin)
        {
            ulong newPosition;
            IntPtr newPositionPointer = new IntPtr(&newPosition);
            this.istream.Seek(offset, (int)origin, newPositionPointer);
            return (long)newPosition;
        }

        public override void SetLength(long value)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value");
            }

            this.istream.SetSize(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset");
            }

            if ((buffer.Length - offset) < count)
            {
                throw new ArgumentException("offset + count > buffer.Length");
            }

            if (offset == 0)
            {
                this.istream.Write(buffer, count, IntPtr.Zero);
            }
            else
            {
                // Note: if a custom offset is specified, we allocate a temp buffer for this write.
                // it'd be nicer to pass the original buffer in, but we can't increment its pointer
                // without using unsafe code.
                byte[] tempBuffer = new byte[count];
                Buffer.BlockCopy(buffer, offset, tempBuffer, 0, count);
                this.istream.Write(tempBuffer, count, IntPtr.Zero);
            }
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    GC.SuppressFinalize(this);
                }

                Marshal.ReleaseComObject(this.istream);
            }
            catch
            {
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace Hashlib.NET.Common
{
    internal static class BitConverterEndian
    {
#if !UNSAFE
        internal static byte[] GetBytesBE(short value)
        {
            byte[] bytes = new byte[sizeof(short)]; // 2
            bytes[0] = (byte)(value >> 8);
            bytes[1] = (byte)(value >> 0);
            return bytes;
        }

        internal static byte[] GetBytesBE(int value)
        {
            byte[] bytes = new byte[sizeof(int)]; // 4
            bytes[0] = (byte)(value >> 24);
            bytes[1] = (byte)(value >> 16);
            bytes[2] = (byte)(value >>  8);
            bytes[3] = (byte)(value >>  0);
            return bytes;
        }

        internal static byte[] GetBytesBE(long value)
        {
            byte[] bytes = new byte[sizeof(long)]; // 8
            bytes[0] = (byte)(value >> 56);
            bytes[1] = (byte)(value >> 48);
            bytes[2] = (byte)(value >> 40);
            bytes[3] = (byte)(value >> 32);
            bytes[4] = (byte)(value >> 24);
            bytes[5] = (byte)(value >> 16);
            bytes[6] = (byte)(value >>  8);
            bytes[7] = (byte)(value >>  0);

            return bytes;
        }

        internal static byte[] GetBytesBE(ushort value)
        {
            return GetBytesBE((short)value);
        }

        internal static byte[] GetBytesBE(uint value)
        {
            return GetBytesBE((int)value);
        }

        internal static byte[] GetBytesBE(ulong value)
        {
            return GetBytesBE((long)value);
        }

        internal static byte[] GetBytesLE(short value)
        {
            byte[] bytes = new byte[sizeof(short)];
            bytes[0] = (byte)(value >> 0);
            bytes[1] = (byte)(value >> 8);
            return bytes;
        }

        internal static byte[] GetBytesLE(int value)
        {
            byte[] bytes = new byte[sizeof(int)]; // 4
            bytes[0] = (byte)(value >>  0);
            bytes[1] = (byte)(value >>  8);
            bytes[2] = (byte)(value >> 16);
            bytes[3] = (byte)(value >> 24);
            return bytes;
        }

        internal static byte[] GetBytesLE(long value)
        {
            byte[] bytes = new byte[sizeof(long)]; // 8
            bytes[0] = (byte)(value >> 0);
            bytes[1] = (byte)(value >> 8);
            bytes[2] = (byte)(value >> 16);
            bytes[3] = (byte)(value >> 24);
            bytes[4] = (byte)(value >> 32);
            bytes[5] = (byte)(value >> 40);
            bytes[6] = (byte)(value >> 48);
            bytes[7] = (byte)(value >> 56);

            return bytes;
        }

        internal static byte[] GetBytesLE(ushort value)
        {
            return GetBytesLE((short)value);
        }

        internal static byte[] GetBytesLE(uint value)
        {
            return GetBytesLE((int)value);
        }

        internal static byte[] GetBytesLE(ulong value)
        {
            return GetBytesLE((long)value);
        }

#else

        [System.Security.SecuritySafeCritical]
        internal static unsafe byte[] GetBytesBE(short value)
        {
            byte[] bytes = new byte[2];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 8);
                *(pbyte + 1) = (byte)(value >> 0);
            }

            return bytes;
        }

        [System.Security.SecuritySafeCritical]
        internal static unsafe byte[] GetBytesBE(int value)
        {
            byte[] bytes = new byte[4];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 24);
                *(pbyte + 1) = (byte)(value >> 16);
                *(pbyte + 2) = (byte)(value >>  8);
                *(pbyte + 3) = (byte)(value >>  0);
            }

            return bytes;
        }

        [System.Security.SecuritySafeCritical]
        internal static unsafe byte[] GetBytesBE(long value)
        {
            byte[] bytes = new byte[8];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 56);
                *(pbyte + 1) = (byte)(value >> 48);
                *(pbyte + 2) = (byte)(value >> 40);
                *(pbyte + 3) = (byte)(value >> 32);
                *(pbyte + 3) = (byte)(value >> 24);
                *(pbyte + 3) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >>  8);
                *(pbyte + 3) = (byte)(value >>  0);
            }

            return bytes;
        }

        internal static unsafe byte[] GetBytesBE(ushort value)
        {
            return GetBytesBE((short)value);
        }

        internal static unsafe byte[] GetBytesBE(uint value)
        {
            return GetBytesBE((int)value);
        }

        internal static unsafe byte[] GetBytesBE(ulong value)
        {
            return GetBytesBE((long)value);
        }

        [System.Security.SecuritySafeCritical]
        public static unsafe byte[] GetBytesLE(short value)
        {
            byte[] bytes = new byte[2];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
            }

            return bytes;
        }

        [System.Security.SecuritySafeCritical]
        public static unsafe byte[] GetBytesLE(int value)
        {
            byte[] bytes = new byte[4];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
                *(pbyte + 2) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >> 24);
            }

            return bytes;
        }

        [System.Security.SecuritySafeCritical]
        public static unsafe byte[] GetBytesLE(long value)
        {
            byte[] bytes = new byte[8];
            fixed (byte* pbyte = bytes)
            {
                *(pbyte + 0) = (byte)(value >> 0);
                *(pbyte + 1) = (byte)(value >> 8);
                *(pbyte + 2) = (byte)(value >> 16);
                *(pbyte + 3) = (byte)(value >> 24);
                *(pbyte + 4) = (byte)(value >> 32);
                *(pbyte + 5) = (byte)(value >> 40);
                *(pbyte + 6) = (byte)(value >> 48);
                *(pbyte + 7) = (byte)(value >> 56);
            }

            return bytes;
        }

        public static unsafe byte[] GetBytesLE(ushort value)
        {
            return GetBytesLE((short)value);
        }

        public static unsafe byte[] GetBytesLE(uint value)
        {
            return GetBytesLE((int)value);
        }

        public static unsafe byte[] GetBytesLE(ulong value)
        {
            return GetBytesLE((long)value);
        }

#endif
    }
}

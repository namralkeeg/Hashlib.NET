#region Copyright

/*
 * Copyright (C) 2018 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#endregion Copyright

using System;

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

        internal static short ToInt16BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(short))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (short)
                (
                (value[startIndex + 0] << 8) |
                (value[startIndex + 1] << 0)
                );
        }

        internal static int ToInt32BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(int))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (int)
                (
                (value[startIndex + 0] << 24) |
                (value[startIndex + 1] << 16) |
                (value[startIndex + 2] << 08) |
                (value[startIndex + 3] << 00)
                );
        }

        internal static long ToInt64BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(long))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (long)
                (
                (value[startIndex + 0] << 56) |
                (value[startIndex + 1] << 48) |
                (value[startIndex + 2] << 40) |
                (value[startIndex + 3] << 32) |
                (value[startIndex + 4] << 24) |
                (value[startIndex + 5] << 16) |
                (value[startIndex + 6] << 08) |
                (value[startIndex + 7] << 00)
                );
        }

        internal static ushort ToUInt16BE(byte[] value, int startIndex)
        {
            return (ushort)ToInt16BE(value, startIndex);
        }

        internal static uint ToUInt32BE(byte[] value, int startIndex)
        {
            return (uint)ToInt32BE(value, startIndex);
        }

        internal static ulong ToUInt64BE(byte[] value, int startIndex)
        {
            return (ulong)ToInt64BE(value, startIndex);
        }

        internal static short ToInt16LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(short))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (short)
                (
                (value[startIndex + 0] << 0) |
                (value[startIndex + 1] << 8)
                );
        }

        internal static int ToInt32LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(int))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (int)
                (
                (value[startIndex + 0] << 00) |
                (value[startIndex + 1] << 08) |
                (value[startIndex + 2] << 16) |
                (value[startIndex + 3] << 24)
                );
        }

        internal static long ToInt64LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(long))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            return (long)
                (
                (value[startIndex + 0] << 00) |
                (value[startIndex + 1] << 08) |
                (value[startIndex + 2] << 16) |
                (value[startIndex + 4] << 32) |
                (value[startIndex + 5] << 40) |
                (value[startIndex + 3] << 24) |
                (value[startIndex + 6] << 48) |
                (value[startIndex + 7] << 56)
                );
        }

        internal static ushort ToUInt16LE(byte[] value, int startIndex)
        {
            return (ushort)ToInt16LE(value, startIndex);
        }

        internal static uint ToUInt32LE(byte[] value, int startIndex)
        {
            return (uint)ToInt32LE(value, startIndex);
        }

        internal static ulong ToUInt64LE(byte[] value, int startIndex)
        {
            return (ulong)ToInt64LE(value, startIndex);
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

        public static unsafe short ToInt16BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(short))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (short)
                    (
                    (*(pbyte + 0) << 8) |
                    (*(pbyte + 1))
                    );
            }
        }

        public static unsafe int ToInt32BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(int))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (int)
                    (
                    (*(pbyte + 0) << 24) |
                    (*(pbyte + 1) << 16) |
                    (*(pbyte + 2) << 8) |
                    (*(pbyte + 3))
                    );
            }
        }

        public static unsafe long ToInt64BE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(long))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (long)
                (
                (*(pbyte + 0) << 56) |
                (*(pbyte + 1) << 48) |
                (*(pbyte + 2) << 40) |
                (*(pbyte + 3) << 32) |
                (*(pbyte + 4) << 24) |
                (*(pbyte + 5) << 16) |
                (*(pbyte + 6) << 8) |
                (*(pbyte + 7))
                );
            }
        }

        public static unsafe ushort ToUInt16BE(byte[] value, int startIndex)
        {
            return (ushort)ToInt16BE(value, startIndex);
        }

        public static unsafe uint ToUInt32BE(byte[] value, int startIndex)
        {
            return (uint)ToInt32BE(value, startIndex);
        }

        public static unsafe ulong ToUInt64BE(byte[] value, int startIndex)
        {
            return (ulong)ToInt64BE(value, startIndex);
        }

        public static unsafe short ToInt16LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(short))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (short)
                    (
                    (*(pbyte + 0)) |
                    (*(pbyte + 1) << 8)
                    );
            }
        }

        public static unsafe int ToInt32LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(int))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (int)
                    (
                    (*(pbyte + 0)) |
                    (*(pbyte + 1) << 8) |
                    (*(pbyte + 2) << 16) |
                    (*(pbyte + 3) << 24)
                    );
            }
        }

        public static unsafe long ToInt64LE(byte[] value, int startIndex)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if ((uint)startIndex >= value.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }
            if (startIndex > value.Length - sizeof(long))
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            fixed (byte* pbyte = &value[startIndex])
            {
                return (long)
                (
                (*(pbyte + 0)) |
                (*(pbyte + 1) << 8) |
                (*(pbyte + 2) << 16) |
                (*(pbyte + 3) << 24) |
                (*(pbyte + 4) << 32) |
                (*(pbyte + 5) << 40) |
                (*(pbyte + 6) << 48) |
                (*(pbyte + 7) << 56)
                );
            }
        }

        public static unsafe ushort ToUInt16LE(byte[] value, int startIndex)
        {
            return (ushort)ToInt16LE(value, startIndex);
        }

        public static unsafe uint ToUInt32LE(byte[] value, int startIndex)
        {
            return (uint)ToInt32LE(value, startIndex);
        }

        public static unsafe ulong ToUInt64LE(byte[] value, int startIndex)
        {
            return (ulong)ToInt64LE(value, startIndex);
        }
#endif
    }
}

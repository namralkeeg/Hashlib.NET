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

using System.Runtime.CompilerServices;

namespace Hashlib.NET.Common
{
    internal static class BitwiseRotate
    {
        #region Rotate Left

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte Rol(this byte value, int count)
        {
            return (byte)((value << count) | (value >> (8 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ushort Rol(this ushort value, int count)
        {
            return (ushort)((value << count) | (value >> (16 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint Rol(this uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong Rol(this ulong value, int count)
        {
            return (value << count) | (value >> (64 - count));
        }

        #endregion Rotate Left

        #region Rotate Right

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte Ror(this byte value, int count)
        {
            return (byte)((value >> count) | (value << (8 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ushort Ror(this ushort value, int count)
        {
            return (ushort)((value >> count) | (value << (16 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint Ror(this uint value, int count)
        {
            return (value >> count) | (value << (32 - count));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong Ror(this ulong value, int count)
        {
            return (value >> count) | (value << (64 - count));
        }

        #endregion Rotate Right

        #region Rotate Left In-Place

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this byte value, int count)
        {
            value = (byte)((value << count) | (value >> (8 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this sbyte value, int count)
        {
            value = (sbyte)(((byte)value << count) | ((byte)value >> (8 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this ushort value, int count)
        {
            value = (ushort)((value << count) | (value >> (16 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this short value, int count)
        {
            value = (short)(((ushort)value << count) | ((ushort)value >> (16 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this uint value, int count)
        {
            value = (value << count) | (value >> (32 - count));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this int value, int count)
        {
            value = (int)(((uint)value << count) | ((uint)value >> (32 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this ulong value, int count)
        {
            value = (ulong)((value << count) | (value >> (64 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Roli(ref this long value, int count)
        {
            value = (long)(((ulong)value << count) | ((ulong)value >> (64 - count)));
        }

        #endregion Rotate Left In-Place

        #region Rotate Right In-Place

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Rori(ref this byte value, int count)
        {
            value = (byte)((value >> count) | (value << (8 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Rori(ref this ushort value, int count)
        {
            value = (ushort)((value >> count) | (value << (16 - count)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Rori(ref this uint value, int count)
        {
            value = (value >> count) | (value << (32 - count));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Rori(ref this ulong value, int count)
        {
            value = (value >> count) | (value << (64 - count));
        }

        #endregion Rotate Right In-Place
    }
}
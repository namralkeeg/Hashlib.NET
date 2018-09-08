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
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.Checksum
{
    /// <summary>
    /// A Fletcher checksum implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// The Fletcher checksum is an algorithm for computing a position-dependent checksum devised by John G. Fletcher.
    /// https://en.wikipedia.org/wiki/Fletcher%27s_checksum
    /// </remarks>
    public sealed class Fletcher32 : HashAlgorithm
    {
        private const uint _modValue = 65535u;
        private const int _BlockSize = 2;
        private uint _sum1;
        private uint _sum2;

        /// <summary>
        /// Initializes an <see cref="Fletcher32"/> class.
        /// </summary>
        public Fletcher32()
        {
            HashSizeValue = 32;
            Initialize();
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Fletcher32"/> class.
        /// </summary>
        /// <returns>A new instance of an <see cref="Fletcher32"/> class.</returns>
        public static new Fletcher32 Create()
        {
            return Create(typeof(Fletcher32).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Fletcher32"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of an <see cref="Fletcher32"/> class.</returns>
        public static new Fletcher32 Create(string hashName)
        {
            return (Fletcher32)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Initializes an instance of <see cref="Fletcher32"/> class.
        /// </summary>
        public override void Initialize()
        {
            _sum1 = 0xFFFFu;
            _sum2 = 0xFFFFu;
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            uint i;
            int length = cbSize / _BlockSize;
            int index = ibStart;
            int remainder = cbSize % _BlockSize;
            for (; length >= 360; length -= 360)
            {
                for (i = 0; i < 360; i++)
                {
                    _sum1 += Get16Bits(array, index);
                    _sum2 += _sum1;
                    index += _BlockSize;
                }

                _sum1 %= _modValue;
                _sum2 %= _modValue;
            }

            for (i = 0; i < length; ++i)
            {
                _sum1 += Get16Bits(array, index);
                _sum2 += _sum1;
                index += _BlockSize;
            }

            if (remainder > 0)
            {
                _sum1 += array[index];
                _sum2 += _sum1;
            }

            _sum1 %= _modValue;
            _sum2 %= _modValue;
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>The computed hash as a byte array.</returns>
        protected override byte[] HashFinal()
        {
            uint hash = _sum2 << 16 | _sum1;
            return BitConverter.GetBytes(hash);
        }

        private ushort Get16Bits(byte[] array, int pos)
        {
            return (ushort)((array[pos + 1] << 8) | array[pos]);
        }
    }
}
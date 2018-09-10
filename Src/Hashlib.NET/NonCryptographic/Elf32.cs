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

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// An ELF 32-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// Similar to the PJW Hash function, but tweaked for 32-bit processors. It is a widley used hash
    /// function on UNIX based systems.
    /// </remarks>
    public sealed class Elf32 : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultDeed = 0;
        private uint _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Elf32"/> class.
        /// </summary>
        public Elf32()
        {
            HashSizeValue = _BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Elf32"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Elf32"/> class.</returns>
        public static new Elf32 Create()
        {
            return Create(typeof(Elf32).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Elf32"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Elf32"/> class.</returns>
        public static new Elf32 Create(string hashName)
        {
            return (Elf32)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Elf32"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _DefaultDeed;
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            uint high = 0u;
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                _hash = (_hash << 4) + array[i];
                high = _hash & 0xF0000000u;
                if (high != 0)
                {
                    _hash ^= high >> 24;
                }

                _hash &= ~high;
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>The computed hash as a byte array.</returns>
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(_hash);
        }

        #endregion Methods
    }
}
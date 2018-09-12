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
    /// A SuperFast hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// The SuperFast algorithm is by Paul Hsieh. http://www.azillionmonkeys.com/qed/hash.html
    /// </remarks>
    public sealed class SuperFast : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultSeed = 0;
        private uint _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="SuperFast"/> class.
        /// </summary>
        public SuperFast()
        {
            HashSizeValue = _BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="SuperFast"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="SuperFast"/> class.</returns>
        public static new SuperFast Create()
        {
            return Create(typeof(SuperFast).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="SuperFast"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SuperFast"/> class.</returns>
        public static new SuperFast Create(string hashName)
        {
            return (SuperFast)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="SuperFast"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _DefaultSeed;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int length = cbSize;
            uint temp;
            int remainder = length & 3;
            int position = ibStart;

            if (cbSize < 1)
            {
                return;
            }

            if (_hash == 0)
            {
                _hash = (uint)length;
            }

            unchecked
            {
                // length = length / 4;
                length >>= 2;

                while (length > 0)
                {
                    _hash += Get16Bits(array, position);
                    position += 2;
                    // Calculations are Little-Endian.
                    temp = (uint)(BitConverterEndian.ToUInt16LE(array, position) << 11) ^ _hash;
                    _hash = (_hash << 16) ^ temp;
                    position += 2;
                    _hash += _hash >> 11;
                    length--;
                }

                // Handle end cases
                switch (remainder)
                {
                    case 3:
                        // Calculations are Little-Endian.
                        _hash += BitConverterEndian.ToUInt16LE(array, position);
                        position += 2;
                        _hash ^= _hash << 16;
                        _hash ^= (byte)(array[position] << 18);
                        _hash += _hash >> 11;
                        break;

                    case 2:
                        // Calculations are Little-Endian.
                        _hash += BitConverterEndian.ToUInt16LE(array, position);
                        _hash ^= _hash << 11;
                        _hash += _hash >> 17;
                        break;

                    case 1:
                        _hash += array[position];
                        _hash ^= _hash << 10;
                        _hash += _hash >> 1;
                        break;

                    default:
                        break;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            unchecked
            {
                // Force "avalanching" of final 127 bits
                _hash ^= _hash << 3;
                _hash += _hash >> 5;
                _hash ^= _hash << 4;
                _hash += _hash >> 17;
                _hash ^= _hash << 25;
                _hash += _hash >> 6;
            }

            return BitConverter.GetBytes(_hash);
        }

        private ushort Get16Bits(byte[] array, int startIndex)
        {
            return (ushort)
                (
                (array[startIndex + 1] << 8) |
                 array[startIndex + 0]
                );
        }

        #endregion Methods
    }
}
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
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.NonCryptographic
{
    public class Fast_Hash : HashAlgorithm
    {
        #region Fields

        private const BitSize _DefaultBitSize = BitSize.Bits32;
        private const ulong _DefaultSeed = 0;
        private const string _InvalidBitSizeMessageTemplate = "Invalid bit size: {0}";
        private const ulong _M = 0x880355F21E6D1965ul;

        private static readonly HashSet<BitSize> _validBitSizes =
            new HashSet<BitSize> { BitSize.Bits32, BitSize.Bits64 };

        private BitSize _bitSize;
        private ulong _hash;
        private ulong _seed;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Fast_Hash"/> class.
        /// </summary>
        public Fast_Hash() : this(_DefaultBitSize, _DefaultSeed)
        { }

        /// <summary>
        /// Initializes a <see cref="Fast_Hash"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size to use for hashing algorithm.</param>
        /// <remarks>Bit size is restricted to 32, and 64.</remarks>
        public Fast_Hash(BitSize bitSize) : this(bitSize, _DefaultSeed)
        { }

        /// <summary>
        /// Initializes a <see cref="Fast_Hash"/> class.
        /// </summary>
        /// <param name="seed">The initial value to set for the hash.</param>
        public Fast_Hash(ulong seed) : this(_DefaultBitSize, seed)
        { }

        /// <summary>
        /// Initializes a <see cref="Fast_Hash"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size to use for hashing algorithm.</param>
        /// <param name="seed">The initial value to set for the hash.</param>
        public Fast_Hash(BitSize bitSize, ulong seed)
        {
            BitSize = bitSize;
            Seed = seed;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the bit size to use for the hashing algorithm. Defaults to 32.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown for invalid bit sizes.</exception>
        /// <remarks>Valid bit sizes are 32 and 64. Defaults to 32.</remarks>
        public BitSize BitSize
        {
            get => _bitSize;
            set
            {
                if (!IsValidBitSize(value))
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        string.Format(_InvalidBitSizeMessageTemplate, value));
                }

                _bitSize = value;
                Initialize();
            }
        }

        /// <inheritdoc/>
        public override int HashSize => (int)_bitSize;

        /// <summary>
        /// Gets and sets the seed value to use for computing the hash.
        /// </summary>
        public ulong Seed
        {
            get => _seed;
            set
            {
                _seed = (_bitSize == BitSize.Bits32) ? (uint)(value & 0xFFFFFFFFu) : value;
                Initialize();
            }
        }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Sets the initial values of a <see cref="Fast_Hash"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _seed;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            Core(array, ibStart, cbSize);
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            _hash = Mix(_hash);

            return (_bitSize == BitSize.Bits32) ?
                BitConverter.GetBytes((uint)(_hash - (_hash >> 32))) :
                BitConverter.GetBytes(_hash);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Core(byte[] array, int ibStart, int cbSize)
        {
            int remainder = cbSize & 7;
            int blockEnd = ibStart + (cbSize - remainder);
            _hash ^= (ulong)cbSize * _M;

            ulong v;
            for (int i = ibStart; i < blockEnd; i += 8)
            {
                v = ToUInt64LE(array, i);
                _hash ^= Mix(v);
                _hash *= _M;
            }

            v = 0;
            switch (remainder)
            {
                case 7: v ^= (ulong)array[blockEnd + 6] << 48; goto case 6;
                case 6: v ^= (ulong)array[blockEnd + 5] << 40; goto case 5;
                case 5: v ^= (ulong)array[blockEnd + 4] << 32; goto case 4;
                case 4: v ^= (ulong)array[blockEnd + 3] << 24; goto case 3;
                case 3: v ^= (ulong)array[blockEnd + 2] << 16; goto case 2;
                case 2: v ^= (ulong)array[blockEnd + 1] << 08; goto case 1;
                case 1: v ^= (ulong)array[blockEnd + 0] << 00;
                    _hash ^= Mix(v);
                    _hash *= _M;
                    break;

                default:
                    break;
            }
        }

        private bool IsValidBitSize(BitSize bitSize)
        {
            return _validBitSizes.Contains(bitSize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ulong Mix(ulong h)
        {
            h ^= h >> 23;
            h *= 0x2127599BF4325C37ul;
            h ^= h >> 47;

            return h;
        }

        #endregion Methods
    }
}
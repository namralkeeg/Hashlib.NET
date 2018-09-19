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
using System.Runtime.CompilerServices;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A MurmurHash3 x86 32-bit hash implementation of the <see cref="MurmurHash32"/> class.
    /// </summary>
    /// <remarks>
    /// MurmurHash3 was written by Austin Appleby.
    /// https://github.com/aappleby/smhasher/tree/master/src
    /// </remarks>
    public sealed class MurmurHash3x86_32 : MurmurHash32
    {
        #region Fields

        private const uint _C1 = 0xCC9E2D51u;
        private const uint _C2 = 0X1B873593u;
        private const uint _DefaultSeed = 0;
        private uint _byteCount;
        private uint _hash;
        private uint _seed;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="MurmurHash3x86_32"/> class.
        /// </summary>
        public MurmurHash3x86_32() : this(_DefaultSeed)
        { }

        /// <summary>
        /// Sets the initial values of a <see cref="MurmurHash3x86_32"/> class.
        /// </summary>
        /// <param name="seed">The initial value to set for the hash.</param>
        public MurmurHash3x86_32(uint seed)
        {
            _seed = seed;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the seed value to use for computing the hash.
        /// </summary>
        public uint Seed
        {
            get => _seed;
            set
            {
                _seed = value;
                Initialize();
            }
        }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Sets the initial values of a <see cref="MurmurHash3x86_32"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _seed;
            _byteCount = 0;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            Core(array, ibStart, cbSize);
            _byteCount += (uint)cbSize;
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            // Finalization
            _hash ^= _byteCount;
            _hash = Fmix32(_hash);

            return BitConverter.GetBytes(_hash);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Core(byte[] array, int ibStart, int cbSize)
        {
            uint k1 = 0;
            int remainder = cbSize & 3;
            int blockEnd = ibStart + (cbSize - remainder);

            // The main body.
            for (int i = ibStart; i < blockEnd; i += 4)
            {
                // Calculation is Little-Endian
                k1 = ToUInt32LE(array, i);

                unchecked
                {
                    k1 = (k1 * _C1).Rol(15) * _C2;
                    _hash = ((_hash ^ k1).Rol(13) * 5) + 0xE6546B64u;
                }
            }

            // Tail end cases.
            k1 = 0;
            unchecked
            {
                switch (remainder)
                {
                    case 03: k1 ^= (uint)array[blockEnd + 2] << 16; goto case 02;
                    case 02: k1 ^= (uint)array[blockEnd + 1] << 08; goto case 01;
                    case 01: k1 ^= (uint)array[blockEnd + 0] << 00;
                        _hash ^= (k1 * _C1).Rol(15) * _C2;
                        break;

                    default:
                        break;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint Fmix32(uint h)
        {
            uint temp = h;
            unchecked
            {
                temp = (temp ^ (temp >> 16)) * 0x85EBCA6Bu;
                temp = (temp ^ (temp >> 13)) * 0xC2B2AE35u;
                temp ^= temp >> 16;
            }

            return temp;
        }

        #endregion Methods
    }
}
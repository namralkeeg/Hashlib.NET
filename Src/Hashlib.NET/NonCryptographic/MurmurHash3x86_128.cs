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
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A MurmurHash3 x86 128-bit hash implementation of the <see cref="MurmurHash128"/> class.
    /// </summary>
    /// <remarks>
    /// MurmurHash3 was written by Austin Appleby.
    /// https://github.com/aappleby/smhasher/tree/master/src
    /// </remarks>
    public sealed class MurmurHash3x86_128 : MurmurHash128
    {
        #region Fields

        private const uint _C1 = 0x239B961Bu;
        private const uint _C2 = 0xAB0E9789u;
        private const uint _C3 = 0x38B34AE5u;
        private const uint _C4 = 0xA1E38B93u;

        private uint _byteCount;
        private uint _hash1;
        private uint _hash2;
        private uint _hash3;
        private uint _hash4;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="MurmurHash3x86_128"/> class.
        /// </summary>
        public MurmurHash3x86_128() : this(_DefaultSeed)
        { }

        /// <summary>
        /// Sets the initial values of a <see cref="MurmurHash3x86_128"/> class.
        /// </summary>
        /// <param name="seed">The initial value to set for the hash.</param>
        public MurmurHash3x86_128(uint seed)
        {
            _seed = seed;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Sets the initial values of a <see cref="MurmurHash3x86_128"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash1 = _seed;
            _hash2 = _seed;
            _hash3 = _seed;
            _hash4 = _seed;
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
            unchecked
            {
                _hash1 ^= _byteCount;
                _hash2 ^= _byteCount;
                _hash3 ^= _byteCount;
                _hash4 ^= _byteCount;
            }

            _hash1 += _hash2 + _hash3 + _hash4;
            _hash2 += _hash1; _hash3 += _hash1; _hash4 += _hash1;

            _hash1 = Fmix32(_hash1);
            _hash2 = Fmix32(_hash2);
            _hash3 = Fmix32(_hash3);
            _hash4 = Fmix32(_hash4);

            _hash1 += _hash2 + _hash3 + _hash4;
            _hash2 += _hash1; _hash3 += _hash1; _hash4 += _hash1;

            byte[] hash = new byte[16];
            SetBytesLE(_hash1, hash, 00);
            SetBytesLE(_hash2, hash, 04);
            SetBytesLE(_hash3, hash, 08);
            SetBytesLE(_hash4, hash, 12);

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Core(byte[] array, int ibStart, int cbSize)
        {
            uint k1, k2, k3, k4;
            int remainder = cbSize & 15;
            int blockEnd = ibStart + (cbSize - remainder);

            // The main body.
            // Process 16 byte blocks.
            for (int i = ibStart; i < blockEnd; i += 16)
            {
                // Calculation is Little-Endian
                k1 = ToUInt32LE(array, i + 00);
                k2 = ToUInt32LE(array, i + 04);
                k3 = ToUInt32LE(array, i + 08);
                k4 = ToUInt32LE(array, i + 12);

                unchecked
                {
                    _hash1 ^= (k1 * _C1).Rol(15) * _C2;
                    _hash1 = ((_hash1.Rol(19) + _hash2) * 5) + 0x561CCD1Bu;

                    _hash2 ^= (k2 * _C2).Rol(16) * _C3;
                    _hash2 = ((_hash2.Rol(17) + _hash1) * 5) + 0x0BCAA747u;

                    _hash3 ^= (k3 * _C3).Rol(17) * _C4;
                    _hash3 = ((_hash3.Rol(15) + _hash4) * 5) + 0x96CD1C35u;

                    _hash4 ^= (k4 * _C4).Rol(18) * _C1;
                    _hash4 = ((_hash4.Rol(13) + _hash1) * 5) + 0x32AC3B17u;
                }
            }

            // Tail end cases.
            k1 = k2 = k3 = k4 = 0;
            unchecked
            {
                switch (remainder)
                {
                    case 15: k4 ^= (uint)array[blockEnd + 14] << 16; goto case 14;
                    case 14: k4 ^= (uint)array[blockEnd + 13] << 08; goto case 13;
                    case 13:
                        k4 ^= (uint)array[blockEnd + 12] << 00;
                        _hash4 ^= (k4 * _C4).Rol(18) * _C1;
                        goto case 12;

                    case 12: k3 ^= (uint)array[blockEnd + 11] << 24; goto case 11;
                    case 11: k3 ^= (uint)array[blockEnd + 10] << 16; goto case 10;
                    case 10: k3 ^= (uint)array[blockEnd + 09] << 08; goto case 09;
                    case 09:
                        k3 ^= (uint)array[blockEnd + 08] << 00;
                        _hash3 ^= (k3 * _C3).Rol(17) * _C4;
                        goto case 08;

                    case 8: k2 ^= (uint)array[blockEnd + 7] << 24; goto case 07;
                    case 7: k2 ^= (uint)array[blockEnd + 6] << 16; goto case 06;
                    case 6: k2 ^= (uint)array[blockEnd + 5] << 08; goto case 05;
                    case 5:
                        k2 ^= (uint)array[blockEnd + 4] << 00;
                        _hash2 ^= (k2 * _C2).Rol(16) * _C3;
                        goto case 04;

                    case 4: k1 ^= (uint)array[blockEnd + 3] << 24; goto case 03;
                    case 3: k1 ^= (uint)array[blockEnd + 2] << 16; goto case 02;
                    case 2: k1 ^= (uint)array[blockEnd + 1] << 08; goto case 01;
                    case 1:
                        k1 ^= (uint)array[blockEnd + 0] << 00;
                        _hash1 ^= (k1 * _C1).Rol(15) * _C2;
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
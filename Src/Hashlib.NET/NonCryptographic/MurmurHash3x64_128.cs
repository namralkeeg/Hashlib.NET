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
using System.Security.Cryptography;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A MurmurHash3 x64 128-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// MurmurHash3 was written by Austin Appleby.
    /// https://github.com/aappleby/smhasher/tree/master/src
    /// </remarks>
    public sealed class MurmurHash3x64_128 : HashAlgorithm
    {
        private const int _BitSize = sizeof(ulong) * 2 * 8; // 8 * 2 * 8 = 128 bits
        private const ulong _C1 = 0x87C37B91114253D5ul;
        private const ulong _C2 = 0x4CF5AD432745937Ful;
        private const ulong _DefaultSeed = 0;

        private ulong _byteCount;
        private ulong _hash1;
        private ulong _hash2;
        private ulong _seed;

        /// <summary>
        /// Initializes a <see cref="MurmurHash3x64_128"/> class.
        /// </summary>
        public MurmurHash3x64_128() : this(_DefaultSeed)
        { }

        /// <summary>
        /// Sets the initial values of a <see cref="MurmurHash3x64_128"/> class.
        /// </summary>
        /// <param name="seed">The initial value to set for the hash.</param>
        public MurmurHash3x64_128(ulong seed)
        {
            HashSizeValue = _BitSize;
            _seed = seed;
            Initialize();
        }

        /// <summary>
        /// Gets and sets the seed value to use for computing the hash.
        /// </summary>
        public ulong Seed
        {
            get => _seed;
            set
            {
                _seed = value;
                Initialize();
            }
        }

        /// <summary>
        /// Creates a new instance of a <see cref="MurmurHash3x64_128"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="MurmurHash3x64_128"/> class.</returns>
        public static new MurmurHash3x64_128 Create()
        {
            return Create(typeof(MurmurHash3x64_128).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="MurmurHash3x64_128"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="MurmurHash3x64_128"/> class.</returns>
        public static new MurmurHash3x64_128 Create(string hashName)
        {
            return (MurmurHash3x64_128)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="MurmurHash3x64_128"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash1 = _seed;
            _hash2 = _seed;
            _byteCount = 0;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            Core(array, ibStart, cbSize);
            _byteCount += (ulong)cbSize;
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            // Finalization
            unchecked
            {
                _hash1 ^= _byteCount;
                _hash2 ^= _byteCount;
            }

            _hash1 += _hash2;
            _hash2 += _hash1;

            _hash1 = Fmix64(_hash1);
            _hash2 = Fmix64(_hash2);

            _hash1 += _hash2;
            _hash2 += _hash1;

            byte[] hash = new byte[16];
            SetBytesLE(_hash1, hash, 00);
            SetBytesLE(_hash2, hash, 08);

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Core(byte[] array, int ibStart, int cbSize)
        {
            ulong k1, k2;
            int remainder = cbSize & 15;
            int blockEnd = ibStart + (cbSize - remainder);

            // The main body.
            // Process 16 byte blocks.
            for (int i = 0; i < blockEnd; i += 16)
            {
                // Calculation is Little-Endian
                k1 = ToUInt64LE(array, i + 00);
                k2 = ToUInt64LE(array, i + 08);

                unchecked
                {
                    _hash1 ^= (k1 * _C1).Rol(31) * _C2;
                    _hash1 = ((_hash1.Rol(27) + _hash2) * 5) + 0x52DCE729ul;

                    _hash2 ^= (k2 * _C2).Rol(33) * _C1;
                    _hash2 = ((_hash2.Rol(31) + _hash1) * 5) + 0x38495AB5ul;
                }
            }

            // Tail end cases.
            k1 = k2 = 0;
            unchecked
            {
                switch (remainder)
                {
                    case 15: k2 ^= ((ulong)array[blockEnd + 14]) << 48; goto case 14;
                    case 14: k2 ^= ((ulong)array[blockEnd + 13]) << 40; goto case 13;
                    case 13: k2 ^= ((ulong)array[blockEnd + 12]) << 32; goto case 12;
                    case 12: k2 ^= ((ulong)array[blockEnd + 11]) << 24; goto case 11;
                    case 11: k2 ^= ((ulong)array[blockEnd + 10]) << 16; goto case 10;
                    case 10: k2 ^= ((ulong)array[blockEnd + 09]) << 08; goto case 09;
                    case 09: k2 ^= ((ulong)array[blockEnd + 08]) << 00;
                        _hash2 ^= (k2 * _C2).Rol(33) * _C1;
                        goto case 08;

                    case 08: k1 ^= ((ulong)array[blockEnd + 07]) << 56; goto case 07;
                    case 07: k1 ^= ((ulong)array[blockEnd + 06]) << 48; goto case 06;
                    case 06: k1 ^= ((ulong)array[blockEnd + 05]) << 40; goto case 05;
                    case 05: k1 ^= ((ulong)array[blockEnd + 04]) << 32; goto case 04;
                    case 04: k1 ^= ((ulong)array[blockEnd + 03]) << 24; goto case 03;
                    case 03: k1 ^= ((ulong)array[blockEnd + 02]) << 16; goto case 02;
                    case 02: k1 ^= ((ulong)array[blockEnd + 01]) << 08; goto case 01;
                    case 01: k1 ^= ((ulong)array[blockEnd + 00]) << 00;
                        _hash1 ^= (k1 * _C1).Rol(31) * _C2;
                        break;

                    default:
                        break;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Fmix64(ulong k)
        {
            ulong temp = k;
            unchecked
            {
                temp = (temp ^ (temp >> 33)) * 0xFF51AFD7ED558CCDul;
                temp = (temp ^ (temp >> 33)) * 0xC4CEB9FE1A85EC53ul;
                temp ^= temp >> 33;
            }

            return temp;
        }
    }
}

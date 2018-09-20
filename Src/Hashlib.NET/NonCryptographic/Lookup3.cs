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
using System.Security.Cryptography;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A Lookup3 hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// Lookup3 was written by Bob Jenkins. See https://en.wikipedia.org/wiki/Jenkins_hash_function
    /// </remarks>
    public sealed class Lookup3 : HashAlgorithm
    {
        #region Fields

        private const BitSize _DefaultBitSize = BitSize.Bits32;
        private const uint _DefaultSeed = 0;
        private const string _InvalidBitSizeMessageTemplate = "Invalid bit size: {0}";
        private const string _PropArrayMustBeLessMessageTemplate = "{0} size must {1} bytes or less in length.";

        private static readonly HashSet<BitSize> _validBitSizes =
            new HashSet<BitSize> { BitSize.Bits32, BitSize.Bits64 };

        private BitSize _bitSize;
        private uint _hashA;
        private uint _hashB;
        private uint _seedA;
        private uint _seedB;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Lookup3"/> class.
        /// </summary>
        public Lookup3() : this(_DefaultBitSize, _DefaultSeed)
        { }

        /// <summary>
        /// Sets the initial values of a <see cref="Lookup3"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size to use for hashing algorithm.</param>
        /// <remarks>Bit size is restricted to 32, and 64.</remarks>
        public Lookup3(BitSize bitSize) : this(bitSize, _DefaultSeed)
        { }

        /// <summary>
        /// Initializes a <see cref="Lookup3"/> class.
        /// </summary>
        /// <param name="seed">The initial value to set for the hash.</param>
        public Lookup3(ulong seed) : this(_DefaultBitSize, seed)
        { }

        /// <summary>
        /// Initializes a <see cref="Lookup3"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size to use for hashing algorithm.</param>
        /// <param name="seed">The initial value to set for the hash.</param>
        /// <remarks>Bit size is restricted to 32, and 64.</remarks>
        public Lookup3(BitSize bitSize, ulong seed)
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
        /// <remarks>Valid bit sizes are 32 and 64.</remarks>
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
            }
        }

        /// <inheritdoc/>
        public override int HashSize => (int)_bitSize;

        /// <summary>
        /// Gets and sets the seed value to use for computing the hash.
        /// </summary>
        /// <value>A <see cref="uint"/> represented as an array of bytes.</value>
        public ulong Seed
        {
            get
            {
                if (_bitSize == BitSize.Bits32)
                {
                    return _seedA;
                }
                else
                {
                    return ((ulong)_seedB << 32) | _seedA;
                }
            }

            set
            {
                _seedA = (uint)(value & uint.MaxValue);
                _seedB = (uint)((value >> 32) & uint.MaxValue);
                Initialize();
            }
        }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Lookup3"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Lookup3"/> class.</returns>
        public static new Lookup3 Create()
        {
            return Create(typeof(Lookup3).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Lookup3"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Lookup3"/> class.</returns>
        public static new Lookup3 Create(string hashName)
        {
            return (Lookup3)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Lookup3"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hashA = _seedA;
            _hashB = _seedB;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            // Internal state.
            uint a, b, c;
            int length = cbSize;
            int currentIndex = 0;

            // Set up the internal state.
            a = b = c = 0xdeadbeefu + (uint)length + _hashA;
            c += _hashB;

            // All but last block: aligned reads and affect 32 bits of (a,b,c)
            while (length > 12)
            {
                // Read 32-bit chunks in Little-Endian.
                a += ToUInt32LE(array, currentIndex + 00);
                b += ToUInt32LE(array, currentIndex + 04);
                c += ToUInt32LE(array, currentIndex + 08);

                // Mix (a, b, c)
                a -= c; a ^= c.Rol(04); c += b;
                b -= a; b ^= a.Rol(06); a += c;
                c -= b; c ^= b.Rol(08); b += a;
                a -= c; a ^= c.Rol(16); c += b;
                b -= a; b ^= a.Rol(19); a += c;
                c -= b; c ^= b.Rol(04); b += a;

                currentIndex += 12;
                length -= 12;
            }

            switch (length)
            {
                case 12: c += (uint)(array[currentIndex + 11] << 24); goto case 11;
                case 11: c += (uint)(array[currentIndex + 10] << 16); goto case 10;
                case 10: c += (uint)(array[currentIndex + 09] << 08); goto case 09;
                case 09: c += (uint)(array[currentIndex + 08] << 00); goto case 08;
                case 08: b += (uint)(array[currentIndex + 07] << 24); goto case 07;
                case 07: b += (uint)(array[currentIndex + 06] << 16); goto case 06;
                case 06: b += (uint)(array[currentIndex + 05] << 08); goto case 05;
                case 05: b += (uint)(array[currentIndex + 04] << 00); goto case 04;
                case 04: a += (uint)(array[currentIndex + 03] << 24); goto case 03;
                case 03: a += (uint)(array[currentIndex + 02] << 16); goto case 02;
                case 02: a += (uint)(array[currentIndex + 01] << 08); goto case 01;
                case 01: a += array[currentIndex + 00];
                    break;

                default:
                    // Zero length strings require no mixing.
                    _hashA = c;
                    _hashB = b;
                    return;
            }

            // Final mixing of 3 32-bit values (a,b,c) into c.
            c ^= b; c -= b.Rol(14);
            a ^= c; a -= c.Rol(11);
            b ^= a; b -= a.Rol(25);
            c ^= b; c -= b.Rol(16);
            a ^= c; a -= c.Rol(04);
            b ^= a; b -= a.Rol(14);
            c ^= b; c -= b.Rol(24);

            // Store the computed hash.
            _hashA = c;
            _hashB = b;
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            if (_bitSize == BitSize.Bits32)
            {
                return BitConverter.GetBytes(_hashA);
            }
            else // _bitSize == 64
            {
                return BitConverter.GetBytes((ulong)_hashB << 32 | _hashA);
            }
        }

        private bool IsValidBitSize(BitSize bitSize)
        {
            return _validBitSizes.Contains(bitSize);
        }

        #endregion Methods
    }
}
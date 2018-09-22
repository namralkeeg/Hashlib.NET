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

namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// A Keccak variable bit length hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// Keccak is based on a novel approach called sponge construction.
    /// https://en.wikipedia.org/wiki/SHA-3
    /// </remarks>
    public sealed class Keccak : HashAlgorithm, IBlockHash
    {
        #region Fields

        private const BitSize _DefaultBitsize = BitSize.Bits256;
        private const string _InvalidBitSizeMessageTemplate = "Invalid bit size: {0}";

        // 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
        private const int _MaxBlockSize = 144;  // 200 - 2 * (224 / 8)
        private const int _StateSize = 25;      // 1600 / (8 * 8)
        private const int _Rounds = 24;

        private static readonly HashSet<BitSize> _validBitSizes;
        private static readonly ulong[] _xorMasks;

        // Bytes not processed yet
        private readonly byte[] _buffer;

        private readonly ulong[] _coefficients;

        // Hash state
        private readonly ulong[] _state;

        private BitSize _bitSize;

        // Block size is less than or equal to Max Block Size. (200 - 2 * (bitSize / 8))
        private int _blockSize;

        // Valid bytes in buffer.
        private int _bufferSize;

        // Size of processed data in bytes
        private long _byteCount;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Sets the initial static values of a <see cref="Keccak"/> class.
        /// </summary>
        static Keccak()
        {
            _xorMasks = new ulong[]
            {
                0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
                0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
                0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
                0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
                0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
                0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
                0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
                0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
            };

            _validBitSizes = new HashSet<BitSize> { BitSize.Bits224, BitSize.Bits256, BitSize.Bits384, BitSize.Bits512 };
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Keccak"/> class.
        /// </summary>
        /// <remarks>The default bit size of the algorithm is 256.</remarks>
        public Keccak() : this(_DefaultBitsize)
        { }

        /// <summary>
        /// Sets the initial values of a <see cref="Keccak"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size to use for hashing algorithm.</param>
        /// <remarks>Bit size is restricted to 224, 245, 384, and 512.</remarks>
        public Keccak(BitSize bitSize)
        {
            _buffer = new byte[_MaxBlockSize];
            _coefficients = new ulong[5];
            _state = new ulong[_StateSize];
            BitSize = bitSize;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the bit size to use for the hashing algorithm. Defaults to 256.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown for invalid bit sizes.</exception>
        /// <remarks>Valid bit sizes are 224, 256, 384, and 512.</remarks>
        public BitSize BitSize
        {
            get => _bitSize;
            set
            {
                if (!IsValidBitSize(value))
                {
                    throw new ArgumentOutOfRangeException(nameof(value), string.Format(_InvalidBitSizeMessageTemplate, value));
                }

                _bitSize = value;
                _blockSize = 200 - 2 * ((int)_bitSize / 8);
                Initialize();
            }
        }

        /// <summary>
        /// The number of bits in the returned hash.
        /// </summary>
        public override int HashSize => (int)_bitSize;

        /// <summary>
        /// The size in bytes of each block that's processed at once.
        /// </summary>
        public int BlockSize => _blockSize;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Keccak"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Keccak"/> class.</returns>
        public static new Keccak Create()
        {
            return Create(typeof(Keccak).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Keccak"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Keccak"/> class.</returns>
        public static new Keccak Create(string hashName)
        {
            return (Keccak)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Keccak"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_state, 0, _state.Length);
            Array.Clear(_buffer, 0, _buffer.Length);
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int bytesLeft = cbSize;
            int current = ibStart;

            // Copy data to the buffer.
            if (_bufferSize > 0)
            {
                while ((bytesLeft > 0) && (_bufferSize < _blockSize))
                {
                    _buffer[_bufferSize++] = array[current++];
                    bytesLeft--;
                }
            }

            // If the buffer is full.
            if (_bufferSize == _blockSize)
            {
                ProcessBlock(_buffer, 0);
                _byteCount += _blockSize;
                _bufferSize = 0;
            }

            // Process the data that's left.
            if (bytesLeft > 0)
            {
                // Process full blocks
                while (bytesLeft >= _blockSize)
                {
                    ProcessBlock(array, current);
                    current += _blockSize;
                    _byteCount += _blockSize;
                    bytesLeft -= _blockSize;
                }

                // Keep the remaining bytes in the buffer.
                while (bytesLeft > 0)
                {
                    _buffer[_bufferSize++] = array[current++];
                    bytesLeft--;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            // Process the remaining bytes.
            ProcessBuffer();

            // number of significant elements in hash
            int hashLength = (int)_bitSize / 64;
            byte[] hashTemp = new byte[(int)_bitSize / 8];
            int current = 0;
            for (int i = 0; i < hashLength; i++, current += 8)
            {
                SetBytesLE(_state[i], hashTemp, current);
            }

            // SHA3-224's last entry in hash provides only 32 bits instead of 64 bits
            int remainder = (int)_bitSize - hashLength * 64;
            if (remainder > 0)
            {
                int processed = 0;
                while (processed < remainder)
                {
                    hashTemp[current++] = (byte)(_state[hashLength] >> processed);
                    processed += 8;
                }
            }

            return hashTemp;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Mod5(uint x)
        {
            // return x % 5 for 0 <= x <= 9
            if (x < 5)
            {
                return x;
            }

            return x - 5;
        }

        private bool IsValidBitSize(BitSize bitSize)
        {
            return _validBitSizes.Contains(bitSize);
        }

        /// <summary>
        /// The core Keccak hashing algorithm.
        /// </summary>
        /// <param name="block">The array of data to process.</param>
        /// <param name="startIndex">The index into the array to start at.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessBlock(byte[] block, int startIndex)
        {
            // Mix data into state
            for (int i = 0, currentByte = startIndex; i < _blockSize / 8; i++, currentByte += 8)
            {
                unchecked
                {
                    _state[i] ^= ToUInt64LE(block, currentByte);
                }
            }

            // Re-compute state
            for (int round = 0; round < _Rounds; round++)
            {
                // Theta
               for (int i = 0; i < 5; i++)
                {
                    unchecked
                    {
                        _coefficients[i] = _state[i] ^ _state[i + 5] ^ _state[i + 10] ^ _state[i + 15] ^ _state[i + 20];
                    }
                }

                ulong one;
                for (uint i = 0; i < 5; i++)
                {
                    unchecked
                    {
                        one = _coefficients[Mod5(i + 4)] ^ _coefficients[Mod5(i + 1)].Rol(1);
                        _state[i + 00] ^= one;
                        _state[i + 05] ^= one;
                        _state[i + 10] ^= one;
                        _state[i + 15] ^= one;
                        _state[i + 20] ^= one;
                    }
                }

                // Rho Pi
                ulong last = _state[1];
                one = _state[10]; _state[10] = last.Rol(01); last = one;
                one = _state[07]; _state[07] = last.Rol(03); last = one;
                one = _state[11]; _state[11] = last.Rol(06); last = one;
                one = _state[17]; _state[17] = last.Rol(10); last = one;
                one = _state[18]; _state[18] = last.Rol(15); last = one;
                one = _state[03]; _state[03] = last.Rol(21); last = one;
                one = _state[05]; _state[05] = last.Rol(28); last = one;
                one = _state[16]; _state[16] = last.Rol(36); last = one;
                one = _state[08]; _state[08] = last.Rol(45); last = one;
                one = _state[21]; _state[21] = last.Rol(55); last = one;
                one = _state[24]; _state[24] = last.Rol(02); last = one;
                one = _state[04]; _state[04] = last.Rol(14); last = one;
                one = _state[15]; _state[15] = last.Rol(27); last = one;
                one = _state[23]; _state[23] = last.Rol(41); last = one;
                one = _state[19]; _state[19] = last.Rol(56); last = one;
                one = _state[13]; _state[13] = last.Rol(08); last = one;
                one = _state[12]; _state[12] = last.Rol(25); last = one;
                one = _state[02]; _state[02] = last.Rol(43); last = one;
                one = _state[20]; _state[20] = last.Rol(62); last = one;
                one = _state[14]; _state[14] = last.Rol(18); last = one;
                one = _state[22]; _state[22] = last.Rol(39); last = one;
                one = _state[09]; _state[09] = last.Rol(61); last = one;
                one = _state[06]; _state[06] = last.Rol(20); last = one;
                _state[1] = last.Rol(44);

                // Chi
                ulong two;
                for (int j = 0; j < 25; j += 5)
                {
                    // Temporaries
                    one = _state[j];
                    two = _state[j + 1];

                    unchecked
                    {
                        _state[j + 0] ^= _state[j + 2] & ~two;
                        _state[j + 1] ^= _state[j + 3] & ~_state[j + 2];
                        _state[j + 2] ^= _state[j + 4] & ~_state[j + 3];
                        _state[j + 3] ^= one & ~_state[j + 4];
                        _state[j + 4] ^= two & ~one;
                    }
                }

                // Iota
                _state[0] ^= _xorMasks[round];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessBuffer()
        {
            // Add padding
            int offset = _bufferSize;

            // Add a "1" byte
            _buffer[offset++] = 1;

            // Fill with zeros
            while (offset < _blockSize)
            {
                _buffer[offset++] = 0;
            }

            // Add a single set bit
            _buffer[offset - 1] |= 0x80;

            // Process the buffer block.
            ProcessBlock(_buffer, 0);
        }

        #endregion Methods
    }
}
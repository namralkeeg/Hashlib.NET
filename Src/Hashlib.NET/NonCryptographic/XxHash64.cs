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
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A XxHash 64-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>XXHash 64-bit, based on Yann Collet's descriptions, see http://cyan4973.github.io/xxHash/ </remarks>
    public sealed class XxHash64 : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(ulong) * 8;
        private const uint _DefaultSeed = 0;

        // temporarily store up to 31 bytes between multiple calls
        private const int _MaxBufferSize = 31 + 1;

        // "magic" constants
        private const ulong _Prime1 = 11400714785074694791ul;
        private const ulong _Prime2 = 14029467366897019727ul;
        private const ulong _Prime3 = 1609587929392839161ul;
        private const ulong _Prime4 = 9650029242287828579ul;
        private const ulong _Prime5 = 2870177450012600261ul;

        // internal state and temporary buffer
        private readonly ulong[] _state;
        private byte[] _buffer;

        private int _bufferSize;
        private ulong _seed;
        private ulong _totalLength;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="XxHash64"/> class.
        /// </summary>
        public XxHash64()
        {
            HashSizeValue = _BitSize;
            _seed = _DefaultSeed;
            _buffer = new byte[_MaxBufferSize];
            _state = new ulong[4];
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the seed value to use.
        /// </summary>
        /// <value>A number to initially seed the hash value with.</value>
        public ulong Seed
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
        /// Creates a new instance of a <see cref="XxHash32"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="XxHash32"/> class.</returns>
        public static new XxHash64 Create()
        {
            return Create(typeof(XxHash64).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="XxHash32"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="XxHash32"/> class.</returns>
        public static new XxHash64 Create(string hashName)
        {
            return (XxHash64)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="XxHash32"/> class.
        /// </summary>
        public override void Initialize()
        {
            _state[0] = _seed + _Prime1 + _Prime2;
            _state[1] = _seed + _Prime2;
            _state[2] = _seed;
            _state[3] = _seed - _Prime1;
            _bufferSize = 0;
            _totalLength = 0;

            Array.Clear(_buffer, 0, _buffer.Length);
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int length = cbSize;
            _totalLength += (ulong)length;
            int current = ibStart;

            // unprocessed old data plus new data still fit in temporary buffer ?
            if (_bufferSize + length < _MaxBufferSize)
            {
                // just add new data
                Buffer.BlockCopy(array, current, _buffer, _bufferSize, length);
                _bufferSize += length;
            }
            else
            {
                int stop = (ibStart + cbSize);
                int stopBlock = stop - _MaxBufferSize;

                // some data left from previous update ?
                if (_bufferSize > 0)
                {
                    // make sure temporary buffer is full (32 bytes)
                    Buffer.BlockCopy(array, current, _buffer, _bufferSize, _MaxBufferSize - _bufferSize);
                    current += _MaxBufferSize - _bufferSize;
                    _bufferSize = _MaxBufferSize;

                    // process these 32 bytes (4x8)
                    Process32(_buffer, 0, ref _state[0], ref _state[1], ref _state[2], ref _state[3]);
                }

                // 32 bytes at once
                while (current <= stopBlock)
                {
                    Process32(array, current, ref _state[0], ref _state[1], ref _state[2], ref _state[3]);
                    current += 32;
                }

                _bufferSize = (stop - current);
                // copy remainder to temporary buffer
                Buffer.BlockCopy(array, current, _buffer, 0, (int)_bufferSize);
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            // fold 256 bit state into one single 64 bit value
            ulong result;
            if (_totalLength >= _MaxBufferSize)
            {
                result = _state[0].Rol(1) +
                         _state[1].Rol(7) +
                         _state[2].Rol(12) +
                         _state[3].Rol(18);
                result = (result ^ ((0 + _state[0] * _Prime2).Rol(31) * _Prime1)) * _Prime1 + _Prime4;
                result = (result ^ ((0 + _state[1] * _Prime2).Rol(31) * _Prime1)) * _Prime1 + _Prime4;
                result = (result ^ ((0 + _state[2] * _Prime2).Rol(31) * _Prime1)) * _Prime1 + _Prime4;
                result = (result ^ ((0 + _state[3] * _Prime2).Rol(31) * _Prime1)) * _Prime1 + _Prime4;
            }
            else
            {
                // internal state wasn't set, therefore original seed is still stored in state2
                result = _state[2] + _Prime5;
            }

            result += _totalLength;

            // at least 8 bytes left ? => eat 8 bytes per step
            int currentByte = 0;
            for (; currentByte + 8 <= _bufferSize; currentByte += 8)
            {
                // Calculations are all Little-Endian
                result = (result ^ ProcessSingle(0, ToUInt64LE(_buffer, currentByte)))
                    .Rol(27) * _Prime1 + _Prime4;
            }

            // 4 bytes left ? => eat those
            if (currentByte + 4 <= _bufferSize)
            {
                // Calculations are all Little-Endian
                result = (result ^ ToUInt32LE(_buffer, currentByte) * _Prime1)
                    .Rol(23) * _Prime2 + _Prime3;
                currentByte += 4;
            }

            // take care of remaining 0..3 bytes, eat 1 byte per step
            while (currentByte != _bufferSize)
            {
                result = (result ^ _buffer[currentByte++] * _Prime5).Rol(11) * _Prime1;
            }

            // mix bits
            result ^= result >> 33;
            result *= _Prime2;
            result ^= result >> 29;
            result *= _Prime3;
            result ^= result >> 32;

            return BitConverter.GetBytes(result);
        }

        private void Process32(byte[] block, int startIndex, ref ulong state0, ref ulong state1, ref ulong state2,
            ref ulong state3)
        {
            // Calculations are all Little-Endian
            unchecked
            {
                state0 = (state0 + ToUInt64LE(block, startIndex + 0 * sizeof(ulong)) * _Prime2).Rol(31) * _Prime1;
                state1 = (state1 + ToUInt64LE(block, startIndex + 1 * sizeof(ulong)) * _Prime2).Rol(31) * _Prime1;
                state2 = (state2 + ToUInt64LE(block, startIndex + 2 * sizeof(ulong)) * _Prime2).Rol(31) * _Prime1;
                state3 = (state3 + ToUInt64LE(block, startIndex + 3 * sizeof(ulong)) * _Prime2).Rol(31) * _Prime1;
            }
        }

        private ulong ProcessSingle(ulong previous, ulong input)
        {
            return (previous + input * _Prime2).Rol(31) * _Prime1;
        }

        #endregion Methods
    }
}

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
    /// A XxHash 32-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>XXHash 32-bit, based on Yann Collet's descriptions, see http://cyan4973.github.io/xxHash/ </remarks>
    public sealed class XxHash32 : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultSeed = 0;

        // temporarily store up to 15 bytes between multiple add() calls
        private const uint _MaxBufferSize = 15 + 1;

        // "magic" constants
        private const uint _Prime1 = 2654435761u;
        private const uint _Prime2 = 2246822519u;
        private const uint _Prime3 = 3266489917u;
        private const uint _Prime4 = 668265263u;
        private const uint _Prime5 = 374761393u;

        // internal state and temporary buffer
        private readonly uint[] _state;
        private byte[] _buffer;

        private uint _bufferSize;
        private uint _seed;
        private ulong _totalLength;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="XxHash32"/> class.
        /// </summary>
        public XxHash32()
        {
            HashSizeValue = _BitSize;
            _seed = _DefaultSeed;
            _state = new uint[4];
            _buffer = new byte[_MaxBufferSize];
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the seed value to use.
        /// </summary>
        /// <value>A number to initially seed the hash value with.</value>
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
        /// Creates a new instance of a <see cref="XxHash32"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="XxHash32"/> class.</returns>
        public static new XxHash32 Create()
        {
            return Create(typeof(XxHash32).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="XxHash32"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="XxHash32"/> class.</returns>
        public static new XxHash32 Create(string hashName)
        {
            return (XxHash32)HashAlgorithmFactory.Create(hashName);
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
            uint length = (uint)cbSize;
            _totalLength += length;
            int current = ibStart;

            // unprocessed old data plus new data still fit in temporary buffer ?
            if (_bufferSize + length < _MaxBufferSize)
            {
                // just add new data
                while (length-- > 0)
                {
                    _buffer[_bufferSize++] = array[current++];
                }
            }
            else
            {
                int stop = (ibStart + cbSize);
                int stopBlock = stop - (int)_MaxBufferSize;
                uint[] tempBuff = new uint[4];
                uint i = 0;

                // some data left from previous update ?
                if (_bufferSize > 0)
                {
                    // make sure temporary buffer is full (16 bytes)
                    while (_bufferSize < _MaxBufferSize)
                    {
                        _buffer[_bufferSize++] = array[current++];
                    }

                    int tempBuffIndex;
                    for (i = 0, tempBuffIndex = 0; i < _bufferSize && tempBuffIndex < 4; i += 4)
                    {
                        tempBuff[tempBuffIndex++] = ToUInt32LE(_buffer, (int)i);
                    }

                    // process these 16 bytes (4x4)
                    unchecked
                    {
                        _state[0] = (_state[0] + tempBuff[0] * _Prime2).Rol(13) * _Prime1;
                        _state[1] = (_state[1] + tempBuff[1] * _Prime2).Rol(13) * _Prime1;
                        _state[2] = (_state[2] + tempBuff[2] * _Prime2).Rol(13) * _Prime1;
                        _state[3] = (_state[3] + tempBuff[3] * _Prime2).Rol(13) * _Prime1;
                    }
                }

                // 16 bytes at once
                while (current <= stopBlock)
                {
                    // Calculations are all Little-Endian
                    for (i = 0; i < sizeof(uint); i++)
                    {
                        tempBuff[i] = ToUInt32LE(array, current);
                        current += sizeof(uint);
                    }

                    // process these 16 bytes (4x4)
                    unchecked
                    {
                        _state[0] = (_state[0] + tempBuff[0] * _Prime2).Rol(13) * _Prime1;
                        _state[1] = (_state[1] + tempBuff[1] * _Prime2).Rol(13) * _Prime1;
                        _state[2] = (_state[2] + tempBuff[2] * _Prime2).Rol(13) * _Prime1;
                        _state[3] = (_state[3] + tempBuff[3] * _Prime2).Rol(13) * _Prime1;
                    }
                }

                _bufferSize = (uint)(stop - current);
                // copy remainder to temporary buffer
                Buffer.BlockCopy(array, current, _buffer, 0, (int)_bufferSize);
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            uint result = (uint)_totalLength;

            // fold 128 bit state into one single 32 bit value
            if (_totalLength >= _MaxBufferSize)
            {
                result += _state[0].Rol(1) +
                          _state[1].Rol(7) +
                          _state[2].Rol(12) +
                          _state[3].Rol(18);
            }
            else
            {
                // internal state wasn't set therefore original seed is still stored in state2
                result += _state[2] + _Prime5;
            }

            uint currentByte = 0;
            // at least 4 bytes left ? => eat 4 bytes per step
            while (currentByte + 4 <= _bufferSize)
            {
                result = (result + ToUInt32LE(_buffer, (int)currentByte) * _Prime3).Rol(17) * _Prime4;
                currentByte += 4;
            }

            // take care of remaining 0..3 bytes, eat 1 byte per step
            while (currentByte != _bufferSize)
            {
                result = (result + _buffer[currentByte++] * _Prime5).Rol(11) * _Prime1;
            }

            // mix bits
            result ^= result >> 15;
            result *= _Prime2;
            result ^= result >> 13;
            result *= _Prime3;
            result ^= result >> 16;

            return BitConverter.GetBytes(result);
        }

        #endregion Methods
    }
}
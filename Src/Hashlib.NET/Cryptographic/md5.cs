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


namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// An MD5 hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value.
    /// https://en.wikipedia.org/wiki/MD5
    /// </remarks>
    public sealed class MD5 : HashAlgorithm, IBlockHash
    {
        #region Fields

        private const int _BitSize = 128;

        /// split into 64 byte blocks (=> 512 bits)
        private const int _BlockSize = 64;       // 512 / 8
        private const uint _HashBytes = 16;
        private const uint _HashValuesCount = 4;  // 16 / 4

        private byte[] _buffer;
        private uint _bufferSize;
        private uint _byteCount;
        private uint[] _md5State;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="MD5"/> class.
        /// </summary>
        public MD5()
        {
            _buffer = new byte[_BlockSize];
            _md5State = new uint[_HashValuesCount];
            HashSizeValue = _BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        public int BlockSize => _BlockSize;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="MD5"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="MD5"/> class.</returns>
        public static new MD5 Create()
        {
            return Create(typeof(MD5).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="MD5"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="MD5"/> class.</returns>
        public static new MD5 Create(string hashName)
        {
            return (MD5)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="MD5"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);

            // according to RFC 1321
            _md5State[0] = 0x67452301u;
            _md5State[1] = 0xefcdab89u;
            _md5State[2] = 0x98badcfeu;
            _md5State[3] = 0x10325476u;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int numBytes = cbSize;
            int current = ibStart;

            // Some data was left in the buffer.
            if (_bufferSize > 0)
            {
                while ((numBytes > 0) && (_bufferSize < _BlockSize))
                {
                    _buffer[_bufferSize++] = array[current++];
                    numBytes--;
                }
            }

            // Full buffer
            if (_bufferSize == _BlockSize)
            {
                ProcessBlock(_buffer, 0);
                _byteCount += _BlockSize;
                _bufferSize = 0;
            }

            if (numBytes > 0)
            {
                // process full blocks
                while (numBytes >= _BlockSize)
                {
                    ProcessBlock(array, current);
                    current += _BlockSize;
                    _byteCount += _BlockSize;
                    numBytes -= _BlockSize;
                }

                // keep remaining bytes in buffer
                while (numBytes > 0)
                {
                    _buffer[_bufferSize++] = array[current++];
                    numBytes--;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            // Save the old hash if the buffer is partially filled.
            var oldHash = new uint[_HashValuesCount];
            Array.Copy(_md5State, oldHash, _md5State.Length);

            // Process the remaining bytes.
            ProcessBuffer();

            // Convert from Little-Endian to bytes.
            var hash = new byte[_HashBytes];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount; i++, hashIndex += 4)
            {
                hash[hashIndex    ] = (byte)(_md5State[i] >> 00);
                hash[hashIndex + 1] = (byte)(_md5State[i] >> 08);
                hash[hashIndex + 2] = (byte)(_md5State[i] >> 16);
                hash[hashIndex + 3] = (byte)(_md5State[i] >> 24);
            }

            // Restore the old hash.
            Array.Copy(oldHash, _md5State, oldHash.Length);

            return hash;
        }

        private uint F1(uint b, uint c, uint d)
        {
            return unchecked(d ^ (b & (c ^ d))); // original: f = (b & c) | ((~b) & d);
        }

        private uint F2(uint b, uint c, uint d)
        {
            return unchecked(c ^ (d & (b ^ c))); // original: f = (b & d) | (c & (~d));
        }

        private uint F3(uint b, uint c, uint d)
        {
            return unchecked(b ^ c ^ d);
        }

        private uint F4(uint b, uint c, uint d)
        {
            return unchecked(c ^ (b | ~d));
        }

        /// <summary>
        /// The core MD5 hashing algorithm. It processes 64 byte blocks at a time.
        /// </summary>
        /// <param name="block">The array of data to process.</param>
        /// <param name="startIndex">The index into the array to start at.</param>
        private void ProcessBlock(byte[] block, int startIndex)
        {
            // get last hash
            uint a = _md5State[0];
            uint b = _md5State[1];
            uint c = _md5State[2];
            uint d = _md5State[3];

            // All calculations are Little-Endian.

            // first round
            uint word00 = ToUInt32LE(block, 0 * sizeof(uint));
            a = (a + F1(b, c, d) + word00 + 0xd76aa478).Rol(7) + b;
            uint word01 = ToUInt32LE(block, 1 * sizeof(uint));
            d = (d + F1(a, b, c) + word01 + 0xe8c7b756).Rol(12) + a;
            uint word02 = ToUInt32LE(block, 2 * sizeof(uint));
            c = (c + F1(d, a, b) + word02 + 0x242070db).Rol(17) + d;
            uint word03 = ToUInt32LE(block, 3 * sizeof(uint));
            b = (b + F1(c, d, a) + word03 + 0xc1bdceee).Rol(22) + c;

            uint word04 = ToUInt32LE(block, 4 * sizeof(uint));
            a = (a + F1(b, c, d) + word04 + 0xf57c0faf).Rol(7) + b;
            uint word05 = ToUInt32LE(block, 5 * sizeof(uint));
            d = (d + F1(a, b, c) + word05 + 0x4787c62a).Rol(12) + a;
            uint word06 = ToUInt32LE(block, 6 * sizeof(uint));
            c = (c + F1(d, a, b) + word06 + 0xa8304613).Rol(17) + d;
            uint word07 = ToUInt32LE(block, 7 * sizeof(uint));
            b = (b + F1(c, d, a) + word07 + 0xfd469501).Rol(22) + c;

            uint word08 = ToUInt32LE(block, 8 * sizeof(uint));
            a = (a + F1(b, c, d) + word08 + 0x698098d8).Rol(7) + b;
            uint word09 = ToUInt32LE(block, 9 * sizeof(uint));
            d = (d + F1(a, b, c) + word09 + 0x8b44f7af).Rol(12) + a;
            uint word10 = ToUInt32LE(block, 10 * sizeof(uint));
            c = (c + F1(d, a, b) + word10 + 0xffff5bb1).Rol(17) + d;
            uint word11 = ToUInt32LE(block, 11 * sizeof(uint));
            b = (b + F1(c, d, a) + word11 + 0x895cd7be).Rol(22) + c;

            uint word12 = ToUInt32LE(block, 12 * sizeof(uint));
            a = (a + F1(b, c, d) + word12 + 0x6b901122).Rol(7) + b;
            uint word13 = ToUInt32LE(block, 13 * sizeof(uint));
            d = (d + F1(a, b, c) + word13 + 0xfd987193).Rol(12) + a;
            uint word14 = ToUInt32LE(block, 14 * sizeof(uint));
            c = (c + F1(d, a, b) + word14 + 0xa679438e).Rol(17) + d;
            uint word15 = ToUInt32LE(block, 15 * sizeof(uint));
            b = (b + F1(c, d, a) + word15 + 0x49b40821).Rol(22) + c;

            // second round
            a = (a + F2(b, c, d) + word01 + 0xf61e2562).Rol(5) + b;
            d = (d + F2(a, b, c) + word06 + 0xc040b340).Rol(9) + a;
            c = (c + F2(d, a, b) + word11 + 0x265e5a51).Rol(14) + d;
            b = (b + F2(c, d, a) + word00 + 0xe9b6c7aa).Rol(20) + c;

            a = (a + F2(b, c, d) + word05 + 0xd62f105d).Rol(5) + b;
            d = (d + F2(a, b, c) + word10 + 0x02441453).Rol(9) + a;
            c = (c + F2(d, a, b) + word15 + 0xd8a1e681).Rol(14) + d;
            b = (b + F2(c, d, a) + word04 + 0xe7d3fbc8).Rol(20) + c;

            a = (a + F2(b, c, d) + word09 + 0x21e1cde6).Rol(5) + b;
            d = (d + F2(a, b, c) + word14 + 0xc33707d6).Rol(9) + a;
            c = (c + F2(d, a, b) + word03 + 0xf4d50d87).Rol(14) + d;
            b = (b + F2(c, d, a) + word08 + 0x455a14ed).Rol(20) + c;

            a = (a + F2(b, c, d) + word13 + 0xa9e3e905).Rol(5) + b;
            d = (d + F2(a, b, c) + word02 + 0xfcefa3f8).Rol(9) + a;
            c = (c + F2(d, a, b) + word07 + 0x676f02d9).Rol(14) + d;
            b = (b + F2(c, d, a) + word12 + 0x8d2a4c8a).Rol(20) + c;

            // third round
            a = (a + F3(b, c, d) + word05 + 0xfffa3942).Rol(4) + b;
            d = (d + F3(a, b, c) + word08 + 0x8771f681).Rol(11) + a;
            c = (c + F3(d, a, b) + word11 + 0x6d9d6122).Rol(16) + d;
            b = (b + F3(c, d, a) + word14 + 0xfde5380c).Rol(23) + c;

            a = (a + F3(b, c, d) + word01 + 0xa4beea44).Rol(4) + b;
            d = (d + F3(a, b, c) + word04 + 0x4bdecfa9).Rol(11) + a;
            c = (c + F3(d, a, b) + word07 + 0xf6bb4b60).Rol(16) + d;
            b = (b + F3(c, d, a) + word10 + 0xbebfbc70).Rol(23) + c;

            a = (a + F3(b, c, d) + word13 + 0x289b7ec6).Rol(4) + b;
            d = (d + F3(a, b, c) + word00 + 0xeaa127fa).Rol(11) + a;
            c = (c + F3(d, a, b) + word03 + 0xd4ef3085).Rol(16) + d;
            b = (b + F3(c, d, a) + word06 + 0x04881d05).Rol(23) + c;

            a = (a + F3(b, c, d) + word09 + 0xd9d4d039).Rol(4) + b;
            d = (d + F3(a, b, c) + word12 + 0xe6db99e5).Rol(11) + a;
            c = (c + F3(d, a, b) + word15 + 0x1fa27cf8).Rol(16) + d;
            b = (b + F3(c, d, a) + word02 + 0xc4ac5665).Rol(23) + c;

            // fourth round
            a = (a + F4(b, c, d) + word00 + 0xf4292244).Rol(6) + b;
            d = (d + F4(a, b, c) + word07 + 0x432aff97).Rol(10) + a;
            c = (c + F4(d, a, b) + word14 + 0xab9423a7).Rol(15) + d;
            b = (b + F4(c, d, a) + word05 + 0xfc93a039).Rol(21) + c;

            a = (a + F4(b, c, d) + word12 + 0x655b59c3).Rol(6) + b;
            d = (d + F4(a, b, c) + word03 + 0x8f0ccc92).Rol(10) + a;
            c = (c + F4(d, a, b) + word10 + 0xffeff47d).Rol(15) + d;
            b = (b + F4(c, d, a) + word01 + 0x85845dd1).Rol(21) + c;

            a = (a + F4(b, c, d) + word08 + 0x6fa87e4f).Rol(6) + b;
            d = (d + F4(a, b, c) + word15 + 0xfe2ce6e0).Rol(10) + a;
            c = (c + F4(d, a, b) + word06 + 0xa3014314).Rol(15) + d;
            b = (b + F4(c, d, a) + word13 + 0x4e0811a1).Rol(21) + c;

            a = (a + F4(b, c, d) + word04 + 0xf7537e82).Rol(6) + b;
            d = (d + F4(a, b, c) + word11 + 0xbd3af235).Rol(10) + a;
            c = (c + F4(d, a, b) + word02 + 0x2ad7d2bb).Rol(15) + d;
            b = (b + F4(c, d, a) + word09 + 0xeb86d391).Rol(21) + c;

            // update hash
            _md5State[0] += a;
            _md5State[1] += b;
            _md5State[2] += c;
            _md5State[3] += d;
        }

        private void ProcessBuffer()
        {
            // The input bytes are considered as bits strings, where the first bit is the most
            // significant bit of the byte.

            // - Append "1" bit to message.
            // - Append "0" bits until message length in bit mod 512 is 448.
            // - Append length as 64-bit integer.

            // The number of bits
            uint paddedLength = _bufferSize * 8;

            // Add one bit set to 1 (always appended)
            paddedLength++;

            // Number of bits must be (numBits % 512) = 448
            uint lower11Bits = paddedLength & 511;
            if (lower11Bits <= 448)
            {
                paddedLength += 448 - lower11Bits;
            }
            else
            {
                paddedLength += 512 + 448 - lower11Bits;
            }

            // Convert from bits to bytes
            paddedLength /= 8;

            // Only needed if additional data flows over into a second block.
            byte[] extra = new byte[_BlockSize];

            // append a "1" bit, 128 => binary 10000000
            if (_bufferSize < _BlockSize)
            {
                _buffer[_bufferSize] = 128;
            }
            else
            {
                extra[0] = 128;
            }

            uint i;
            for (i = _bufferSize + 1; i < _BlockSize; i++)
            {
                _buffer[i] = 0;
            }

            for (; i < paddedLength; i++)
            {
                extra[i - _BlockSize] = 0;
            }

            // Add a message length in bits as 64 bit number.
            ulong msgBits = 8 * (_byteCount + _bufferSize);

            // Find the right position.
            uint addLength;
            if (paddedLength < _BlockSize)
            {
                addLength = paddedLength;

                // Must be little endian.
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                _buffer[addLength++] = (byte)(msgBits & 0xFF);
            }
            else
            {
                addLength = paddedLength - _BlockSize;

                // Must be little endian.
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF); msgBits >>= 8;
                extra[addLength++] = (byte)(msgBits & 0xFF);
            }

            // Process the blocks.
            ProcessBlock(_buffer, 0);

            // If it flowed over into a second block.
            if (paddedLength > _BlockSize)
            {
                ProcessBlock(extra, 0);
            }
        }

        #endregion Methods
    }
}

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
    /// A SHA1 hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function which takes an input and
    /// produces a 160-bit (20-byte) hash value known as a message digest - typically rendered as a
    /// hexadecimal number, 40 digits long.
    /// https://en.wikipedia.org/wiki/SHA-1
    /// </remarks>
    public sealed class SHA1 : HashAlgorithm, ICryptographicBlockHash
    {
        #region Fields

        // Hash is 160 bits long.
        private const int _BitSize = 160;

        // Split into 64 byte blocks (=> 512 bits)
        private const int _BlockSize = 64; // 512 / 8

        // Hash is 20 bytes long.
        private const uint _HashBytes = 20;

        private const uint _HashValuesCount = 5; // 20 / 4

        // Calculation round constants.
        private const uint _K1 = 0x5a827999;

        private const uint _K2 = 0x6ed9eba1;
        private const uint _K3 = 0x8f1bbcdc;
        private const uint _K4 = 0xca62c1d6;

        private readonly byte[] _buffer;
        private readonly uint[] _sha1State;
        private readonly uint[] _words;
        private uint _bufferSize;
        private uint _byteCount;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="SHA1"/> class.
        /// </summary>
        public SHA1()
        {
            HashSizeValue = _BitSize;
            _buffer = new byte[_BlockSize];
            _sha1State = new uint[_HashValuesCount];
            _words = new uint[80];
            Initialize();
        }

        #endregion Constructors

        #region Properties

        public int BlockSize => _BlockSize;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="SHA1"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="SHA1"/> class.</returns>
        public static new SHA1 Create()
        {
            return Create(typeof(SHA1).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="SHA1"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SHA1"/> class.</returns>
        public static new SHA1 Create(string hashName)
        {
            return (SHA1)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="SHA1"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
            Array.Clear(_words, 0, _words.Length);

            // According to RFC 1321.
            _sha1State[0] = 0x67452301u;
            _sha1State[1] = 0xefcdab89u;
            _sha1State[2] = 0x98badcfeu;
            _sha1State[3] = 0x10325476u;
            _sha1State[4] = 0xc3d2e1f0u;
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
                // Process full blocks.
                while (numBytes >= _BlockSize)
                {
                    ProcessBlock(array, current);
                    current += _BlockSize;
                    _byteCount += _BlockSize;
                    numBytes -= _BlockSize;
                }

                // Keep the remaining bytes in buffer.
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
            uint[] oldHash = new uint[_HashValuesCount];
            Array.Copy(_sha1State, oldHash, _sha1State.Length);

            // Process the remaining bytes.
            ProcessBuffer();

            // Convert from Big-Endian to bytes.
            byte[] hash = new byte[_HashBytes];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount; i++, hashIndex += 4)
            {
                hash[hashIndex + 0] = (byte)(_sha1State[i] >> 24);
                hash[hashIndex + 1] = (byte)(_sha1State[i] >> 16);
                hash[hashIndex + 2] = (byte)(_sha1State[i] >> 08);
                hash[hashIndex + 3] = (byte)(_sha1State[i] >> 00);
            }

            // Restore the old hash.
            Array.Copy(oldHash, _sha1State, oldHash.Length);

            return hash;
        }

        private uint F1(uint b, uint c, uint d)
        {
            return unchecked(d ^ (b & (c ^ d))); // original: f = (b & c) | ((~b) & d);
        }

        private uint F2(uint b, uint c, uint d)
        {
            return unchecked(b ^ c ^ d);
        }

        private uint F3(uint b, uint c, uint d)
        {
            return unchecked((b & c) | (b & d) | (c & d));
        }

        /// <summary>
        /// The core SHA1 hashing algorithm. It processes 64 byte blocks at a time.
        /// </summary>
        /// <param name="block">The array of data to process.</param>
        /// <param name="startIndex">The index into the array to start at.</param>
        private void ProcessBlock(byte[] block, int startIndex)
        {
            // Get the last hash.
            uint a = _sha1State[0];
            uint b = _sha1State[1];
            uint c = _sha1State[2];
            uint d = _sha1State[3];
            uint e = _sha1State[4];

            int current = startIndex;
            int i;
            // Convert to Big-Endian.
            for (i = 0; i < 16; i++, current += 4)
            {
                _words[i] = ToUInt32BE(block, current);
            }

            // Extend to 80 words.
            for (i = 16; i < 32; i++)
            {
                _words[i] = (_words[i - 3] ^ _words[i - 8] ^ _words[i - 14] ^ _words[i - 16]).Rol(1);
            }

            // This transformation keeps all operands 64-bit aligned and, by removing the dependency
            // of w[i] on w[i-3], allows efficient SIMD implementation with a vector length of 4 like
            // x86 SSE instructions.
            // http://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1/
            for (i = 32; i < 80; i++)
            {
                _words[i] = (_words[i - 6] ^ _words[i - 16] ^ _words[i - 28] ^ _words[i - 32]).Rol(2);
            }

            // first round
            for (i = 0; i < 4; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F1(b, c, d) + _words[offset + 0] + _K1; b = b.Rol(30);
                d += e.Rol(5) + F1(a, b, c) + _words[offset + 1] + _K1; a = a.Rol(30);
                c += d.Rol(5) + F1(e, a, b) + _words[offset + 2] + _K1; e = e.Rol(30);
                b += c.Rol(5) + F1(d, e, a) + _words[offset + 3] + _K1; d = d.Rol(30);
                a += b.Rol(5) + F1(c, d, e) + _words[offset + 4] + _K1; c = c.Rol(30);
            }

            // second round
            for (i = 4; i < 8; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F2(b, c, d) + _words[offset + 0] + _K2; b = b.Rol(30);
                d += e.Rol(5) + F2(a, b, c) + _words[offset + 1] + _K2; a = a.Rol(30);
                c += d.Rol(5) + F2(e, a, b) + _words[offset + 2] + _K2; e = e.Rol(30);
                b += c.Rol(5) + F2(d, e, a) + _words[offset + 3] + _K2; d = d.Rol(30);
                a += b.Rol(5) + F2(c, d, e) + _words[offset + 4] + _K2; c = c.Rol(30);
            }

            // third round
            for (i = 8; i < 12; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F3(b, c, d) + _words[offset + 0] + _K3; b = b.Rol(30);
                d += e.Rol(5) + F3(a, b, c) + _words[offset + 1] + _K3; a = a.Rol(30);
                c += d.Rol(5) + F3(e, a, b) + _words[offset + 2] + _K3; e = e.Rol(30);
                b += c.Rol(5) + F3(d, e, a) + _words[offset + 3] + _K3; d = d.Rol(30);
                a += b.Rol(5) + F3(c, d, e) + _words[offset + 4] + _K3; c = c.Rol(30);
            }

            // fourth round
            for (i = 12; i < 16; i++)
            {
                int offset = 5 * i;
                e += a.Rol(5) + F2(b, c, d) + _words[offset + 0] + _K4; b = b.Rol(30);
                d += e.Rol(5) + F2(a, b, c) + _words[offset + 1] + _K4; a = a.Rol(30);
                c += d.Rol(5) + F2(e, a, b) + _words[offset + 2] + _K4; e = e.Rol(30);
                b += c.Rol(5) + F2(d, e, a) + _words[offset + 3] + _K4; d = d.Rol(30);
                a += b.Rol(5) + F2(c, d, e) + _words[offset + 4] + _K4; c = c.Rol(30);
            }

            // update hash
            _sha1State[0] += a;
            _sha1State[1] += b;
            _sha1State[2] += c;
            _sha1State[3] += d;
            _sha1State[4] += e;
        }

        private void ProcessBuffer()
        {
            // The input bytes are considered as bits strings, where the first bit is the most
            // significant bit of the byte.

            // Append "1" bit to message.
            // Append "0" bits until message length in bit mod 512 is 448.
            // Append length as 64 bit integer.

            // The number of bits.
            uint paddedLength = _bufferSize * 8;

            // Add one bit set to 1 (always appended)
            paddedLength++;

            // The number of bits must be (numBits % 512) = 448
            uint lower11Bits = paddedLength & 511;
            if (lower11Bits <= 448)
            {
                paddedLength += 448 - lower11Bits;
            }
            else
            {
                paddedLength += 512 + 448 - lower11Bits;
            }

            // Convert from bits to bytes.
            paddedLength /= 8;

            // Only needed if additional data flows over into a second block.
            var extra = new byte[_BlockSize];

            // Append a "1" bit, 128 => binary 10000000
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

            // Add the message length in bits as 64-bit number.
            ulong msgBits = 8 * (_byteCount + _bufferSize);

            // Find the right position.
            uint addLength;
            if (paddedLength < _BlockSize)
            {
                addLength = paddedLength;

                // Must be Big-Endian
                _buffer[addLength++] = (byte)((msgBits >> 56) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 48) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 40) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 32) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 24) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 16) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 8) & 0xFF);
                _buffer[addLength++] = (byte)(msgBits & 0xFF);
            }
            else
            {
                addLength = paddedLength - _BlockSize;

                // Must be Big-Endian
                extra[addLength++] = (byte)((msgBits >> 56) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 48) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 40) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 32) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 24) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 16) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 8) & 0xFF);
                extra[addLength++] = (byte)(msgBits & 0xFF);
            }

            // Process the block.
            ProcessBlock(_buffer, 0);

            // if it flowed over into a second block.
            if (paddedLength > _BlockSize)
            {
                ProcessBlock(extra, 0);
            }
        }

        #endregion Methods
    }
}
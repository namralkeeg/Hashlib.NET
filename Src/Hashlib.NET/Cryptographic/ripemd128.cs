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
using System.Security.Cryptography;
using System.Threading.Tasks;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// A RIPEMD 128-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks> https://en.wikipedia.org/wiki/RIPEMD </remarks>
    public class RIPEMD128 : HashAlgorithm, IBlockHash
    {
        #region Fields

        // Hash is 160 bits long.
        private const int _BitSize = 128;

        // Split into 64 byte blocks (=> 512 bits)
        private const int _BlockSize = 64; // 512 / 8

        // Hash is 20 bytes long.
        private const uint _HashBytes = 16;

        private const uint _HashValuesCount = 4; // 16 / 4

        private readonly byte[] _buffer;
        private readonly uint[] _ripemdState;
        private readonly uint[] _words;
        private uint _bufferSize;
        private uint _byteCount;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="RIPEMD128"/> class.
        /// </summary>
        public RIPEMD128()
        {
            HashSizeValue = _BitSize;
            _buffer = new byte[_BlockSize];
            _ripemdState = new uint[_HashValuesCount];
            _words = new uint[16];
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets the size in bytes of each block that's processed at once.
        /// </summary>
        public int BlockSize => _BlockSize;

        /// <summary>
        /// Gets and sets if the core hash algorithm should execute in parallel.
        /// </summary>
        public bool InParallel { get; set; }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="RIPEMD128"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="RIPEMD128"/> class.</returns>
        public static new RIPEMD128 Create()
        {
            return Create(typeof(RIPEMD128).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="RIPEMD128"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="RIPEMD128"/> class.</returns>
        public static new RIPEMD128 Create(string hashName)
        {
            return (RIPEMD128)HashAlgorithmFactory.Create(hashName);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void FFF(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // F(x ^ y ^ z)
                a += (b ^ c ^ d) + x;
                a = (a << s) | (a >> (32 - s));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void II(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // I((b & d) | (c & ~d))
                a += ((b & d) | (c & ~d)) + x + 0x8f1bbcdcu;
                a = (a << s) | (a >> (32 - s));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void III(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // I((b & d) | (c & ~d))
                a += ((b & d) | (c & ~d)) + x + 0x50a28be6u;
                a = (a << s) | (a >> (32 - s));
            }
        }

        /// <summary>
        /// Sets the initial values of a <see cref="RIPEMD128"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
            Array.Clear(_words, 0, _words.Length);

            // Use the same IVs as in SHA1, but Little-Endian. (Same as MD4/5)
            _ripemdState[0] = 0x67452301u;
            _ripemdState[1] = 0xefcdab89u;
            _ripemdState[2] = 0x98badcfeu;
            _ripemdState[3] = 0x10325476u;
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
            Array.Copy(_ripemdState, oldHash, _ripemdState.Length);

            // Process the remaining bytes.
            ProcessBuffer();

            // Convert from Little-Endian to bytes.
            byte[] hash = new byte[_HashBytes];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount; i++, hashIndex += 4)
            {
                SetBytesLE(_ripemdState[i], hash, hashIndex);
            }

            // Restore the old hash.
            Array.Copy(oldHash, _ripemdState, oldHash.Length);

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void FF(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // F(x ^ y ^ z)
                a += (b ^ c ^ d) + x;
                a = (a << s) | (a >> (32 - s));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void GG(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // G((x & y) | (~x & z));
                a += ((b & c) | (~b & d)) + x + 0x5a827999u;
                a = (a << s) | (a >> (32 - s));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void GGG(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // G((x & y) | (~x & z));
                a += ((b & c) | (~b & d)) + x + 0x6d703ef3u;
                a = (a << s) | (a >> (32 - s));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void HH(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // H((b | ~c) ^ d)
                a += ((b | ~c) ^ d) + x + 0x6ed9eba1u;
                a = (a << s) | (a >> (32 - s));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void HHH(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            unchecked
            {
                // H((b | ~c) ^ d)
                a += ((b | ~c) ^ d) + x + 0x5c4dd124u;
                a = (a << s) | (a >> (32 - s));
            }
        }

        private void Left(ref uint aa, ref uint bb, ref uint cc, ref uint dd)
        {
            /* round 1 */
            FF(ref aa, bb, cc, dd, _words[00], 11);
            FF(ref dd, aa, bb, cc, _words[01], 14);
            FF(ref cc, dd, aa, bb, _words[02], 15);
            FF(ref bb, cc, dd, aa, _words[03], 12);
            FF(ref aa, bb, cc, dd, _words[04], 05);
            FF(ref dd, aa, bb, cc, _words[05], 08);
            FF(ref cc, dd, aa, bb, _words[06], 07);
            FF(ref bb, cc, dd, aa, _words[07], 09);
            FF(ref aa, bb, cc, dd, _words[08], 11);
            FF(ref dd, aa, bb, cc, _words[09], 13);
            FF(ref cc, dd, aa, bb, _words[10], 14);
            FF(ref bb, cc, dd, aa, _words[11], 15);
            FF(ref aa, bb, cc, dd, _words[12], 06);
            FF(ref dd, aa, bb, cc, _words[13], 07);
            FF(ref cc, dd, aa, bb, _words[14], 09);
            FF(ref bb, cc, dd, aa, _words[15], 08);

            /* round 2 */
            GG(ref aa, bb, cc, dd, _words[07], 07);
            GG(ref dd, aa, bb, cc, _words[04], 06);
            GG(ref cc, dd, aa, bb, _words[13], 08);
            GG(ref bb, cc, dd, aa, _words[01], 13);
            GG(ref aa, bb, cc, dd, _words[10], 11);
            GG(ref dd, aa, bb, cc, _words[06], 09);
            GG(ref cc, dd, aa, bb, _words[15], 07);
            GG(ref bb, cc, dd, aa, _words[03], 15);
            GG(ref aa, bb, cc, dd, _words[12], 07);
            GG(ref dd, aa, bb, cc, _words[00], 12);
            GG(ref cc, dd, aa, bb, _words[09], 15);
            GG(ref bb, cc, dd, aa, _words[05], 09);
            GG(ref aa, bb, cc, dd, _words[02], 11);
            GG(ref dd, aa, bb, cc, _words[14], 07);
            GG(ref cc, dd, aa, bb, _words[11], 13);
            GG(ref bb, cc, dd, aa, _words[08], 12);

            /* round 3 */
            HH(ref aa, bb, cc, dd, _words[03], 11);
            HH(ref dd, aa, bb, cc, _words[10], 13);
            HH(ref cc, dd, aa, bb, _words[14], 06);
            HH(ref bb, cc, dd, aa, _words[04], 07);
            HH(ref aa, bb, cc, dd, _words[09], 14);
            HH(ref dd, aa, bb, cc, _words[15], 09);
            HH(ref cc, dd, aa, bb, _words[08], 13);
            HH(ref bb, cc, dd, aa, _words[01], 15);
            HH(ref aa, bb, cc, dd, _words[02], 14);
            HH(ref dd, aa, bb, cc, _words[07], 08);
            HH(ref cc, dd, aa, bb, _words[00], 13);
            HH(ref bb, cc, dd, aa, _words[06], 06);
            HH(ref aa, bb, cc, dd, _words[13], 05);
            HH(ref dd, aa, bb, cc, _words[11], 12);
            HH(ref cc, dd, aa, bb, _words[05], 07);
            HH(ref bb, cc, dd, aa, _words[12], 05);

            /* round 4 */
            II(ref aa, bb, cc, dd, _words[01], 11);
            II(ref dd, aa, bb, cc, _words[09], 12);
            II(ref cc, dd, aa, bb, _words[11], 14);
            II(ref bb, cc, dd, aa, _words[10], 15);
            II(ref aa, bb, cc, dd, _words[00], 14);
            II(ref dd, aa, bb, cc, _words[08], 15);
            II(ref cc, dd, aa, bb, _words[12], 09);
            II(ref bb, cc, dd, aa, _words[04], 08);
            II(ref aa, bb, cc, dd, _words[13], 09);
            II(ref dd, aa, bb, cc, _words[03], 14);
            II(ref cc, dd, aa, bb, _words[07], 05);
            II(ref bb, cc, dd, aa, _words[15], 06);
            II(ref aa, bb, cc, dd, _words[14], 08);
            II(ref dd, aa, bb, cc, _words[05], 06);
            II(ref cc, dd, aa, bb, _words[06], 05);
            II(ref bb, cc, dd, aa, _words[02], 12);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessBlock(byte[] block, int startIndex)
        {
            uint aa = _ripemdState[0];
            uint bb = _ripemdState[1];
            uint cc = _ripemdState[2];
            uint dd = _ripemdState[3];

            uint aaa = aa;
            uint bbb = bb;
            uint ccc = cc;
            uint ddd = dd;

            // Convert to Little-Endian.
            for (int i = 0, j = startIndex; i < 16; i++, j += 4)
            {
                _words[i] = ToUInt32LE(block, j);
            }

            if (InParallel)
            {
                // Left and Right can be computed in parallel.
                Parallel.Invoke
                    (
                        () => Left(ref aa, ref bb, ref cc, ref dd),
                        () => Right(ref aaa, ref bbb, ref ccc, ref ddd)
                    );
            }
            else
            {
                Left(ref aa, ref bb, ref cc, ref dd);
                Right(ref aaa, ref bbb, ref ccc, ref ddd);
            }

            // Update the state of the hash object
            ddd += cc + _ripemdState[1];
            _ripemdState[1] = _ripemdState[2] + dd + aaa;
            _ripemdState[2] = _ripemdState[3] + aa + bbb;
            _ripemdState[3] = _ripemdState[0] + bb + ccc;
            _ripemdState[0] = ddd;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessBuffer()
        {
            // The input bytes are considered as bits strings, where the first bit is the most
            // significant bit of the byte.

            // Append "1" bit to message.
            // Append "0" bits until message length in bit mod 512 is 448.
            // Append length as 64-bit integer.

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
                _buffer[_bufferSize] = 0x80; // 128
            }
            else
            {
                extra[0] = 0x80; // 128
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

                // Must be Little-Endian.
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

                // Must be Little-Endian.
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

        private void Right(ref uint aaa, ref uint bbb, ref uint ccc, ref uint ddd)
        {
            /* parallel round 1 */
            III(ref aaa, bbb, ccc, ddd, _words[05], 08);
            III(ref ddd, aaa, bbb, ccc, _words[14], 09);
            III(ref ccc, ddd, aaa, bbb, _words[07], 09);
            III(ref bbb, ccc, ddd, aaa, _words[00], 11);
            III(ref aaa, bbb, ccc, ddd, _words[09], 13);
            III(ref ddd, aaa, bbb, ccc, _words[02], 15);
            III(ref ccc, ddd, aaa, bbb, _words[11], 15);
            III(ref bbb, ccc, ddd, aaa, _words[04], 05);
            III(ref aaa, bbb, ccc, ddd, _words[13], 07);
            III(ref ddd, aaa, bbb, ccc, _words[06], 07);
            III(ref ccc, ddd, aaa, bbb, _words[15], 08);
            III(ref bbb, ccc, ddd, aaa, _words[08], 11);
            III(ref aaa, bbb, ccc, ddd, _words[01], 14);
            III(ref ddd, aaa, bbb, ccc, _words[10], 14);
            III(ref ccc, ddd, aaa, bbb, _words[03], 12);
            III(ref bbb, ccc, ddd, aaa, _words[12], 06);

            /* parallel round 2 */
            HHH(ref aaa, bbb, ccc, ddd, _words[06], 09);
            HHH(ref ddd, aaa, bbb, ccc, _words[11], 13);
            HHH(ref ccc, ddd, aaa, bbb, _words[03], 15);
            HHH(ref bbb, ccc, ddd, aaa, _words[07], 07);
            HHH(ref aaa, bbb, ccc, ddd, _words[00], 12);
            HHH(ref ddd, aaa, bbb, ccc, _words[13], 08);
            HHH(ref ccc, ddd, aaa, bbb, _words[05], 09);
            HHH(ref bbb, ccc, ddd, aaa, _words[10], 11);
            HHH(ref aaa, bbb, ccc, ddd, _words[14], 07);
            HHH(ref ddd, aaa, bbb, ccc, _words[15], 07);
            HHH(ref ccc, ddd, aaa, bbb, _words[08], 12);
            HHH(ref bbb, ccc, ddd, aaa, _words[12], 07);
            HHH(ref aaa, bbb, ccc, ddd, _words[04], 06);
            HHH(ref ddd, aaa, bbb, ccc, _words[09], 15);
            HHH(ref ccc, ddd, aaa, bbb, _words[01], 13);
            HHH(ref bbb, ccc, ddd, aaa, _words[02], 11);

            /* parallel round 3 */
            GGG(ref aaa, bbb, ccc, ddd, _words[15], 09);
            GGG(ref ddd, aaa, bbb, ccc, _words[05], 07);
            GGG(ref ccc, ddd, aaa, bbb, _words[01], 15);
            GGG(ref bbb, ccc, ddd, aaa, _words[03], 11);
            GGG(ref aaa, bbb, ccc, ddd, _words[07], 08);
            GGG(ref ddd, aaa, bbb, ccc, _words[14], 06);
            GGG(ref ccc, ddd, aaa, bbb, _words[06], 06);
            GGG(ref bbb, ccc, ddd, aaa, _words[09], 14);
            GGG(ref aaa, bbb, ccc, ddd, _words[11], 12);
            GGG(ref ddd, aaa, bbb, ccc, _words[08], 13);
            GGG(ref ccc, ddd, aaa, bbb, _words[12], 05);
            GGG(ref bbb, ccc, ddd, aaa, _words[02], 14);
            GGG(ref aaa, bbb, ccc, ddd, _words[10], 13);
            GGG(ref ddd, aaa, bbb, ccc, _words[00], 13);
            GGG(ref ccc, ddd, aaa, bbb, _words[04], 07);
            GGG(ref bbb, ccc, ddd, aaa, _words[13], 05);

            /* parallel round 4 */
            FFF(ref aaa, bbb, ccc, ddd, _words[08], 15);
            FFF(ref ddd, aaa, bbb, ccc, _words[06], 05);
            FFF(ref ccc, ddd, aaa, bbb, _words[04], 08);
            FFF(ref bbb, ccc, ddd, aaa, _words[01], 11);
            FFF(ref aaa, bbb, ccc, ddd, _words[03], 14);
            FFF(ref ddd, aaa, bbb, ccc, _words[11], 14);
            FFF(ref ccc, ddd, aaa, bbb, _words[15], 06);
            FFF(ref bbb, ccc, ddd, aaa, _words[00], 14);
            FFF(ref aaa, bbb, ccc, ddd, _words[05], 06);
            FFF(ref ddd, aaa, bbb, ccc, _words[12], 09);
            FFF(ref ccc, ddd, aaa, bbb, _words[02], 12);
            FFF(ref bbb, ccc, ddd, aaa, _words[13], 09);
            FFF(ref aaa, bbb, ccc, ddd, _words[09], 12);
            FFF(ref ddd, aaa, bbb, ccc, _words[07], 05);
            FFF(ref ccc, ddd, aaa, bbb, _words[10], 15);
            FFF(ref bbb, ccc, ddd, aaa, _words[14], 08);
        }

        #endregion Methods
    }
}
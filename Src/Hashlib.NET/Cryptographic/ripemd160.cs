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
    /// A RIPEMD 160-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks> https://en.wikipedia.org/wiki/RIPEMD </remarks>
    public class RIPEMD160 : HashAlgorithm, ICryptographicBlockHash
    {
        #region Fields

        // Hash is 160 bits long.
        private const int _BitSize = 160;

        // Split into 64 byte blocks (=> 512 bits)
        private const int _BlockSize = 64; // 512 / 8

        // Hash is 20 bytes long.
        private const uint _HashBytes = 20;

        private const uint _HashValuesCount = 5; // 20 / 4

        private readonly byte[] _buffer;
        private readonly uint[] _ripemdState;
        private readonly uint[] _words;
        private uint _bufferSize;
        private uint _byteCount;
        private bool _inParallel;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="RIPEMD160"/> class.
        /// </summary>
        public RIPEMD160()
        {
            HashSizeValue = _BitSize;
            _buffer = new byte[_BlockSize];
            _ripemdState = new uint[_HashValuesCount];
            _words = new uint[16];
            _inParallel = false;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets if the core hash algorithm should execute in parallel.
        /// </summary>
        public bool InParallel { get => _inParallel; set => _inParallel = value; }

        /// <summary>
        /// Gets the size in bytes of each block that's processed at once.
        /// </summary>
        public int BlockSize => _BlockSize;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="RIPEMD160"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="RIPEMD160"/> class.</returns>
        public static new RIPEMD160 Create()
        {
            return Create(typeof(RIPEMD160).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="RIPEMD160"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SHA1"/> class.</returns>
        public static new RIPEMD160 Create(string hashName)
        {
            return (RIPEMD160)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="RIPEMD160"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
            Array.Clear(_words, 0, _words.Length);

            // Use the same IVs as in SHA1, but Little-Endian. (Same as MD4/5)
            _ripemdState[0] = 0x67452301;
            _ripemdState[1] = 0xefcdab89;
            _ripemdState[2] = 0x98badcfe;
            _ripemdState[3] = 0x10325476;
            _ripemdState[4] = 0xc3d2e1f0;
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
        private static uint F(uint x, uint y, uint z)
        {
            return (x ^ y ^ z);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint G(uint x, uint y, uint z)
        {
            return ((x & y) | (~x & z));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint H(uint x, uint y, uint z)
        {
            return ((x | ~y) ^ z);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint I(uint x, uint y, uint z)
        {
            return ((x & z) | (y & ~z));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint J(uint x, uint y, uint z)
        {
            return (x ^ (y | ~z));
        }

        private void Left(ref uint aa, ref uint bb, ref uint cc, ref uint dd, ref uint ee)
        {
            // Left Round 1
            // FF(ref aa, ref bb, ref cc, ref dd, ref ee, _words[0], 11);
            aa += _words[0] + F(bb, cc, dd);
            aa = (aa << 11 | aa >> (32 - 11)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // FF(ref ee, ref aa, ref bb, ref cc, ref dd, _words[1], 14);
            ee += _words[1] + F(aa, bb, cc);
            ee = (ee << 14 | ee >> (32 - 14)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // FF(ref dd, ref ee, ref aa, ref bb, ref cc, _words[2], 15);
            dd += _words[2] + F(ee, aa, bb);
            dd = (dd << 15 | dd >> (32 - 15)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // FF(ref cc, ref dd, ref ee, ref aa, ref bb, _words[3], 12);
            cc += _words[3] + F(dd, ee, aa);
            cc = (cc << 12 | cc >> (32 - 12)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // FF(ref bb, ref cc, ref dd, ref ee, ref aa, _words[4], 5);
            bb += _words[4] + F(cc, dd, ee);
            bb = (bb << 5 | bb >> (32 - 5)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // FF(ref aa, ref bb, ref cc, ref dd, ref ee, _words[5], 8);
            aa += _words[5] + F(bb, cc, dd);
            aa = (aa << 8 | aa >> (32 - 8)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // FF(ref ee, ref aa, ref bb, ref cc, ref dd, _words[6], 7);
            ee += _words[6] + F(aa, bb, cc);
            ee = (ee << 7 | ee >> (32 - 7)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // FF(ref dd, ref ee, ref aa, ref bb, ref cc, _words[7], 9);
            dd += _words[7] + F(ee, aa, bb);
            dd = (dd << 9 | dd >> (32 - 9)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // FF(ref cc, ref dd, ref ee, ref aa, ref bb, _words[8], 11);
            cc += _words[8] + F(dd, ee, aa);
            cc = (cc << 11 | cc >> (32 - 11)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // FF(ref bb, ref cc, ref dd, ref ee, ref aa, _words[9], 13);
            bb += _words[9] + F(cc, dd, ee);
            bb = (bb << 13 | bb >> (32 - 13)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // FF(ref aa, ref bb, ref cc, ref dd, ref ee, _words[10], 14);
            aa += _words[10] + F(bb, cc, dd);
            aa = (aa << 14 | aa >> (32 - 14)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // FF(ref ee, ref aa, ref bb, ref cc, ref dd, _words[11], 15);
            ee += _words[11] + F(aa, bb, cc);
            ee = (ee << 15 | ee >> (32 - 15)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // FF(ref dd, ref ee, ref aa, ref bb, ref cc, _words[12], 6);
            dd += _words[12] + F(ee, aa, bb);
            dd = (dd << 6 | dd >> (32 - 6)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // FF(ref cc, ref dd, ref ee, ref aa, ref bb, _words[13], 7);
            cc += _words[13] + F(dd, ee, aa);
            cc = (cc << 7 | cc >> (32 - 7)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // FF(ref bb, ref cc, ref dd, ref ee, ref aa, _words[14], 9);
            bb += _words[14] + F(cc, dd, ee);
            bb = (bb << 9 | bb >> (32 - 9)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // FF(ref aa, ref bb, ref cc, ref dd, ref ee, _words[15], 8);
            aa += _words[15] + F(bb, cc, dd);
            aa = (aa << 8 | aa >> (32 - 8)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // Left Round 2
            // GG(ref ee, ref aa, ref bb, ref cc, ref dd, _words[7], 7);
            ee += G(aa, bb, cc) + _words[7] + 0x5a827999;
            ee = (ee << 7 | ee >> (32 - 7)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // GG(ref dd, ref ee, ref aa, ref bb, ref cc, _words[4], 6);
            dd += G(ee, aa, bb) + _words[4] + 0x5a827999;
            dd = (dd << 6 | dd >> (32 - 6)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // GG(ref cc, ref dd, ref ee, ref aa, ref bb, _words[13], 8);
            cc += G(dd, ee, aa) + _words[13] + 0x5a827999;
            cc = (cc << 8 | cc >> (32 - 8)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // GG(ref bb, ref cc, ref dd, ref ee, ref aa, _words[1], 13);
            bb += G(cc, dd, ee) + _words[1] + 0x5a827999;
            bb = (bb << 13 | bb >> (32 - 13)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // GG(ref aa, ref bb, ref cc, ref dd, ref ee, _words[10], 11);
            aa += G(bb, cc, dd) + _words[10] + 0x5a827999;
            aa = (aa << 11 | aa >> (32 - 11)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // GG(ref ee, ref aa, ref bb, ref cc, ref dd, _words[6], 9);
            ee += G(aa, bb, cc) + _words[6] + 0x5a827999;
            ee = (ee << 9 | ee >> (32 - 9)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // GG(ref dd, ref ee, ref aa, ref bb, ref cc, _words[15], 7);
            dd += G(ee, aa, bb) + _words[15] + 0x5a827999;
            dd = (dd << 7 | dd >> (32 - 7)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // GG(ref cc, ref dd, ref ee, ref aa, ref bb, _words[3], 15);
            cc += G(dd, ee, aa) + _words[3] + 0x5a827999;
            cc = (cc << 15 | cc >> (32 - 15)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // GG(ref bb, ref cc, ref dd, ref ee, ref aa, _words[12], 7);
            bb += G(cc, dd, ee) + _words[12] + 0x5a827999;
            bb = (bb << 7 | bb >> (32 - 7)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // GG(ref aa, ref bb, ref cc, ref dd, ref ee, _words[0], 12);
            aa += G(bb, cc, dd) + _words[0] + 0x5a827999;
            aa = (aa << 12 | aa >> (32 - 12)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // GG(ref ee, ref aa, ref bb, ref cc, ref dd, _words[9], 15);
            ee += G(aa, bb, cc) + _words[9] + 0x5a827999;
            ee = (ee << 15 | ee >> (32 - 15)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // GG(ref dd, ref ee, ref aa, ref bb, ref cc, _words[5], 9);
            dd += G(ee, aa, bb) + _words[5] + 0x5a827999;
            dd = (dd << 9 | dd >> (32 - 9)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // GG(ref cc, ref dd, ref ee, ref aa, ref bb, _words[2], 11);
            cc += G(dd, ee, aa) + _words[2] + 0x5a827999;
            cc = (cc << 11 | cc >> (32 - 11)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // GG(ref bb, ref cc, ref dd, ref ee, ref aa, _words[14], 7);
            bb += G(cc, dd, ee) + _words[14] + 0x5a827999;
            bb = (bb << 7 | bb >> (32 - 7)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // GG(ref aa, ref bb, ref cc, ref dd, ref ee, _words[11], 13);
            aa += G(bb, cc, dd) + _words[11] + 0x5a827999;
            aa = (aa << 13 | aa >> (32 - 13)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // GG(ref ee, ref aa, ref bb, ref cc, ref dd, _words[8], 12);
            ee += G(aa, bb, cc) + _words[8] + 0x5a827999;
            ee = (ee << 12 | ee >> (32 - 12)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // Left Round 3
            // HH(ref dd, ref ee, ref aa, ref bb, ref cc, _words[3], 11);
            dd += H(ee, aa, bb) + _words[3] + 0x6ed9eba1;
            dd = (dd << 11 | dd >> (32 - 11)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // HH(ref cc, ref dd, ref ee, ref aa, ref bb, _words[10], 13);
            cc += H(dd, ee, aa) + _words[10] + 0x6ed9eba1;
            cc = (cc << 13 | cc >> (32 - 13)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // HH(ref bb, ref cc, ref dd, ref ee, ref aa, _words[14], 6);
            bb += H(cc, dd, ee) + _words[14] + 0x6ed9eba1;
            bb = (bb << 6 | bb >> (32 - 6)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // HH(ref aa, ref bb, ref cc, ref dd, ref ee, _words[4], 7);
            aa += H(bb, cc, dd) + _words[4] + 0x6ed9eba1;
            aa = (aa << 7 | aa >> (32 - 7)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // HH(ref ee, ref aa, ref bb, ref cc, ref dd, _words[9], 14);
            ee += H(aa, bb, cc) + _words[9] + 0x6ed9eba1;
            ee = (ee << 14 | ee >> (32 - 14)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // HH(ref dd, ref ee, ref aa, ref bb, ref cc, _words[15], 9);
            dd += H(ee, aa, bb) + _words[15] + 0x6ed9eba1;
            dd = (dd << 9 | dd >> (32 - 9)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // HH(ref cc, ref dd, ref ee, ref aa, ref bb, _words[8], 13);
            cc += H(dd, ee, aa) + _words[8] + 0x6ed9eba1;
            cc = (cc << 13 | cc >> (32 - 13)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // HH(ref bb, ref cc, ref dd, ref ee, ref aa, _words[1], 15);
            bb += H(cc, dd, ee) + _words[1] + 0x6ed9eba1;
            bb = (bb << 15 | bb >> (32 - 15)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // HH(ref aa, ref bb, ref cc, ref dd, ref ee, _words[2], 14);
            aa += H(bb, cc, dd) + _words[2] + 0x6ed9eba1;
            aa = (aa << 14 | aa >> (32 - 14)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // HH(ref ee, ref aa, ref bb, ref cc, ref dd, _words[7], 8);
            ee += H(aa, bb, cc) + _words[7] + 0x6ed9eba1;
            ee = (ee << 8 | ee >> (32 - 8)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // HH(ref dd, ref ee, ref aa, ref bb, ref cc, _words[0], 13);
            dd += H(ee, aa, bb) + _words[0] + 0x6ed9eba1;
            dd = (dd << 13 | dd >> (32 - 13)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // HH(ref cc, ref dd, ref ee, ref aa, ref bb, _words[6], 6);
            cc += H(dd, ee, aa) + _words[6] + 0x6ed9eba1;
            cc = (cc << 6 | cc >> (32 - 6)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // HH(ref bb, ref cc, ref dd, ref ee, ref aa, _words[13], 5);
            bb += H(cc, dd, ee) + _words[13] + 0x6ed9eba1;
            bb = (bb << 5 | bb >> (32 - 5)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // HH(ref aa, ref bb, ref cc, ref dd, ref ee, _words[11], 12);
            aa += H(bb, cc, dd) + _words[11] + 0x6ed9eba1;
            aa = (aa << 12 | aa >> (32 - 12)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // HH(ref ee, ref aa, ref bb, ref cc, ref dd, _words[5], 7);
            ee += H(aa, bb, cc) + _words[5] + 0x6ed9eba1;
            ee = (ee << 7 | ee >> (32 - 7)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // HH(ref dd, ref ee, ref aa, ref bb, ref cc, _words[12], 5);
            dd += H(ee, aa, bb) + _words[12] + 0x6ed9eba1;
            dd = (dd << 5 | dd >> (32 - 5)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // Left Round 4
            // II(ref cc, ref dd, ref ee, ref aa, ref bb, _words[1], 11);
            cc += I(dd, ee, aa) + _words[1] + 0x8f1bbcdc;
            cc = (cc << 11 | cc >> (32 - 11)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // II(ref bb, ref cc, ref dd, ref ee, ref aa, _words[9], 12);
            bb += I(cc, dd, ee) + _words[9] + 0x8f1bbcdc;
            bb = (bb << 12 | bb >> (32 - 12)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // II(ref aa, ref bb, ref cc, ref dd, ref ee, _words[11], 14);
            aa += I(bb, cc, dd) + _words[11] + 0x8f1bbcdc;
            aa = (aa << 14 | aa >> (32 - 14)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // II(ref ee, ref aa, ref bb, ref cc, ref dd, _words[10], 15);
            ee += I(aa, bb, cc) + _words[10] + 0x8f1bbcdc;
            ee = (ee << 15 | ee >> (32 - 15)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // II(ref dd, ref ee, ref aa, ref bb, ref cc, _words[0], 14);
            dd += I(ee, aa, bb) + _words[0] + 0x8f1bbcdc;
            dd = (dd << 14 | dd >> (32 - 14)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // II(ref cc, ref dd, ref ee, ref aa, ref bb, _words[8], 15);
            cc += I(dd, ee, aa) + _words[8] + 0x8f1bbcdc;
            cc = (cc << 15 | cc >> (32 - 15)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // II(ref bb, ref cc, ref dd, ref ee, ref aa, _words[12], 9);
            bb += I(cc, dd, ee) + _words[12] + 0x8f1bbcdc;
            bb = (bb << 9 | bb >> (32 - 9)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // II(ref aa, ref bb, ref cc, ref dd, ref ee, _words[4], 8);
            aa += I(bb, cc, dd) + _words[4] + 0x8f1bbcdc;
            aa = (aa << 8 | aa >> (32 - 8)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // II(ref ee, ref aa, ref bb, ref cc, ref dd, _words[13], 9);
            ee += I(aa, bb, cc) + _words[13] + 0x8f1bbcdc;
            ee = (ee << 9 | ee >> (32 - 9)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // II(ref dd, ref ee, ref aa, ref bb, ref cc, _words[3], 14);
            dd += I(ee, aa, bb) + _words[3] + 0x8f1bbcdc;
            dd = (dd << 14 | dd >> (32 - 14)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // II(ref cc, ref dd, ref ee, ref aa, ref bb, _words[7], 5);
            cc += I(dd, ee, aa) + _words[7] + 0x8f1bbcdc;
            cc = (cc << 5 | cc >> (32 - 5)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // II(ref bb, ref cc, ref dd, ref ee, ref aa, _words[15], 6);
            bb += I(cc, dd, ee) + _words[15] + 0x8f1bbcdc;
            bb = (bb << 6 | bb >> (32 - 6)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // II(ref aa, ref bb, ref cc, ref dd, ref ee, _words[14], 8);
            aa += I(bb, cc, dd) + _words[14] + 0x8f1bbcdc;
            aa = (aa << 8 | aa >> (32 - 8)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // II(ref ee, ref aa, ref bb, ref cc, ref dd, _words[5], 6);
            ee += I(aa, bb, cc) + _words[5] + 0x8f1bbcdc;
            ee = (ee << 6 | ee >> (32 - 6)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // II(ref dd, ref ee, ref aa, ref bb, ref cc, _words[6], 5);
            dd += I(ee, aa, bb) + _words[6] + 0x8f1bbcdc;
            dd = (dd << 5 | dd >> (32 - 5)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // II(ref cc, ref dd, ref ee, ref aa, ref bb, _words[2], 12);
            cc += I(dd, ee, aa) + _words[2] + 0x8f1bbcdc;
            cc = (cc << 12 | cc >> (32 - 12)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // Left Round 5
            // JJ(ref bb, ref cc, ref dd, ref ee, ref aa, _words[4], 9);
            bb += J(cc, dd, ee) + _words[4] + 0xa953fd4e;
            bb = (bb << 9 | bb >> (32 - 9)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // JJ(ref aa, ref bb, ref cc, ref dd, ref ee, _words[0], 15);
            aa += J(bb, cc, dd) + _words[0] + 0xa953fd4e;
            aa = (aa << 15 | aa >> (32 - 15)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // JJ(ref ee, ref aa, ref bb, ref cc, ref dd, _words[5], 5);
            ee += J(aa, bb, cc) + _words[5] + 0xa953fd4e;
            ee = (ee << 5 | ee >> (32 - 5)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // JJ(ref dd, ref ee, ref aa, ref bb, ref cc, _words[9], 11);
            dd += J(ee, aa, bb) + _words[9] + 0xa953fd4e;
            dd = (dd << 11 | dd >> (32 - 11)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // JJ(ref cc, ref dd, ref ee, ref aa, ref bb, _words[7], 6);
            cc += J(dd, ee, aa) + _words[7] + 0xa953fd4e;
            cc = (cc << 6 | cc >> (32 - 6)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // JJ(ref bb, ref cc, ref dd, ref ee, ref aa, _words[12], 8);
            bb += J(cc, dd, ee) + _words[12] + 0xa953fd4e;
            bb = (bb << 8 | bb >> (32 - 8)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // JJ(ref aa, ref bb, ref cc, ref dd, ref ee, _words[2], 13);
            aa += J(bb, cc, dd) + _words[2] + 0xa953fd4e;
            aa = (aa << 13 | aa >> (32 - 13)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // JJ(ref ee, ref aa, ref bb, ref cc, ref dd, _words[10], 12);
            ee += J(aa, bb, cc) + _words[10] + 0xa953fd4e;
            ee = (ee << 12 | ee >> (32 - 12)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // JJ(ref dd, ref ee, ref aa, ref bb, ref cc, _words[14], 5);
            dd += J(ee, aa, bb) + _words[14] + 0xa953fd4e;
            dd = (dd << 5 | dd >> (32 - 5)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // JJ(ref cc, ref dd, ref ee, ref aa, ref bb, _words[1], 12);
            cc += J(dd, ee, aa) + _words[1] + 0xa953fd4e;
            cc = (cc << 12 | cc >> (32 - 12)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // JJ(ref bb, ref cc, ref dd, ref ee, ref aa, _words[3], 13);
            bb += J(cc, dd, ee) + _words[3] + 0xa953fd4e;
            bb = (bb << 13 | bb >> (32 - 13)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));

            // JJ(ref aa, ref bb, ref cc, ref dd, ref ee, _words[8], 14);
            aa += J(bb, cc, dd) + _words[8] + 0xa953fd4e;
            aa = (aa << 14 | aa >> (32 - 14)) + ee;
            cc = (cc << 10 | cc >> (32 - 10));

            // JJ(ref ee, ref aa, ref bb, ref cc, ref dd, _words[11], 11);
            ee += J(aa, bb, cc) + _words[11] + 0xa953fd4e;
            ee = (ee << 11 | ee >> (32 - 11)) + dd;
            bb = (bb << 10 | bb >> (32 - 10));

            // JJ(ref dd, ref ee, ref aa, ref bb, ref cc, _words[6], 8);
            dd += J(ee, aa, bb) + _words[6] + 0xa953fd4e;
            dd = (dd << 8 | dd >> (32 - 8)) + cc;
            aa = (aa << 10 | aa >> (32 - 10));

            // JJ(ref cc, ref dd, ref ee, ref aa, ref bb, _words[15], 5);
            cc += J(dd, ee, aa) + _words[15] + 0xa953fd4e;
            cc = (cc << 5 | cc >> (32 - 5)) + bb;
            ee = (ee << 10 | ee >> (32 - 10));

            // JJ(ref bb, ref cc, ref dd, ref ee, ref aa, _words[13], 6);
            bb += J(cc, dd, ee) + _words[13] + 0xa953fd4e;
            bb = (bb << 6 | bb >> (32 - 6)) + aa;
            dd = (dd << 10 | dd >> (32 - 10));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessBlock(byte[] block, int startIndex)
        {
            uint aa = _ripemdState[0];
            uint bb = _ripemdState[1];
            uint cc = _ripemdState[2];
            uint dd = _ripemdState[3];
            uint ee = _ripemdState[4];

            uint aaa = aa;
            uint bbb = bb;
            uint ccc = cc;
            uint ddd = dd;
            uint eee = ee;

            // Convert to Little-Endian.
            for (int i = 0, j = startIndex; i < 16; i++, j += 4)
            {
                _words[i] = ToUInt32LE(block, j);
            }

            if (_inParallel)
            {
                // Left and Right can be computed in parallel.
                Parallel.Invoke
                    (
                        () => Left(ref aa, ref bb, ref cc, ref dd, ref ee),
                        () => Right(ref aaa, ref bbb, ref ccc, ref ddd, ref eee)
                    );
            }
            else
            {
                Left(ref aa, ref bb, ref cc, ref dd, ref ee);
                Right(ref aaa, ref bbb, ref ccc, ref ddd, ref eee);
            }

            // Update the state of the hash object
            ddd += cc + _ripemdState[1];
            _ripemdState[1] = _ripemdState[2] + dd + eee;
            _ripemdState[2] = _ripemdState[3] + ee + aaa;
            _ripemdState[3] = _ripemdState[4] + aa + bbb;
            _ripemdState[4] = _ripemdState[0] + bb + ccc;
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

        private void Right(ref uint aaa, ref uint bbb, ref uint ccc, ref uint ddd, ref uint eee)
        {
            // Parallel Right Round 1
            // JJJ(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[5], 8);
            aaa += J(bbb, ccc, ddd) + _words[5] + 0x50a28be6;
            aaa = (aaa << 8 | aaa >> (32 - 8)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // JJJ(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[14], 9);
            eee += J(aaa, bbb, ccc) + _words[14] + 0x50a28be6;
            eee = (eee << 9 | eee >> (32 - 9)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // JJJ(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[7], 9);
            ddd += J(eee, aaa, bbb) + _words[7] + 0x50a28be6;
            ddd = (ddd << 9 | ddd >> (32 - 9)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // JJJ(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[0], 11);
            ccc += J(ddd, eee, aaa) + _words[0] + 0x50a28be6;
            ccc = (ccc << 11 | ccc >> (32 - 11)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // JJJ(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[9], 13);
            bbb += J(ccc, ddd, eee) + _words[9] + 0x50a28be6;
            bbb = (bbb << 13 | bbb >> (32 - 13)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // JJJ(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[2], 15);
            aaa += J(bbb, ccc, ddd) + _words[2] + 0x50a28be6;
            aaa = (aaa << 15 | aaa >> (32 - 15)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // JJJ(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[11], 15);
            eee += J(aaa, bbb, ccc) + _words[11] + 0x50a28be6;
            eee = (eee << 15 | eee >> (32 - 15)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // JJJ(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[4], 5);
            ddd += J(eee, aaa, bbb) + _words[4] + 0x50a28be6;
            ddd = (ddd << 5 | ddd >> (32 - 5)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // JJJ(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[13], 7);
            ccc += J(ddd, eee, aaa) + _words[13] + 0x50a28be6;
            ccc = (ccc << 7 | ccc >> (32 - 7)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // JJJ(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[6], 7);
            bbb += J(ccc, ddd, eee) + _words[6] + 0x50a28be6;
            bbb = (bbb << 7 | bbb >> (32 - 7)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // JJJ(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[15], 8);
            aaa += J(bbb, ccc, ddd) + _words[15] + 0x50a28be6;
            aaa = (aaa << 8 | aaa >> (32 - 8)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // JJJ(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[8], 11);
            eee += J(aaa, bbb, ccc) + _words[8] + 0x50a28be6;
            eee = (eee << 11 | eee >> (32 - 11)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // JJJ(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[1], 14);
            ddd += J(eee, aaa, bbb) + _words[1] + 0x50a28be6;
            ddd = (ddd << 14 | ddd >> (32 - 14)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // JJJ(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[10], 14);
            ccc += J(ddd, eee, aaa) + _words[10] + 0x50a28be6;
            ccc = (ccc << 14 | ccc >> (32 - 14)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // JJJ(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[3], 12);
            bbb += J(ccc, ddd, eee) + _words[3] + 0x50a28be6;
            bbb = (bbb << 12 | bbb >> (32 - 12)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // JJJ(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[12], 6);
            aaa += J(bbb, ccc, ddd) + _words[12] + 0x50a28be6;
            aaa = (aaa << 6 | aaa >> (32 - 6)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // Parallel Right Round 2
            // III(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[6], 9);
            eee += I(aaa, bbb, ccc) + _words[6] + 0x5c4dd124;
            eee = (eee << 9 | eee >> (32 - 9)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // III(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[11], 13);
            ddd += I(eee, aaa, bbb) + _words[11] + 0x5c4dd124;
            ddd = (ddd << 13 | ddd >> (32 - 13)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // III(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[3], 15);
            ccc += I(ddd, eee, aaa) + _words[3] + 0x5c4dd124;
            ccc = (ccc << 15 | ccc >> (32 - 15)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // III(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[7], 7);
            bbb += I(ccc, ddd, eee) + _words[7] + 0x5c4dd124;
            bbb = (bbb << 7 | bbb >> (32 - 7)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // III(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[0], 12);
            aaa += I(bbb, ccc, ddd) + _words[0] + 0x5c4dd124;
            aaa = (aaa << 12 | aaa >> (32 - 12)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // III(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[13], 8);
            eee += I(aaa, bbb, ccc) + _words[13] + 0x5c4dd124;
            eee = (eee << 8 | eee >> (32 - 8)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // III(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[5], 9);
            ddd += I(eee, aaa, bbb) + _words[5] + 0x5c4dd124;
            ddd = (ddd << 9 | ddd >> (32 - 9)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // III(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[10], 11);
            ccc += I(ddd, eee, aaa) + _words[10] + 0x5c4dd124;
            ccc = (ccc << 11 | ccc >> (32 - 11)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // III(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[14], 7);
            bbb += I(ccc, ddd, eee) + _words[14] + 0x5c4dd124;
            bbb = (bbb << 7 | bbb >> (32 - 7)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // III(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[15], 7);
            aaa += I(bbb, ccc, ddd) + _words[15] + 0x5c4dd124;
            aaa = (aaa << 7 | aaa >> (32 - 7)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // III(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[8], 12);
            eee += I(aaa, bbb, ccc) + _words[8] + 0x5c4dd124;
            eee = (eee << 12 | eee >> (32 - 12)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // III(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[12], 7);
            ddd += I(eee, aaa, bbb) + _words[12] + 0x5c4dd124;
            ddd = (ddd << 7 | ddd >> (32 - 7)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // III(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[4], 6);
            ccc += I(ddd, eee, aaa) + _words[4] + 0x5c4dd124;
            ccc = (ccc << 6 | ccc >> (32 - 6)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // III(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[9], 15);
            bbb += I(ccc, ddd, eee) + _words[9] + 0x5c4dd124;
            bbb = (bbb << 15 | bbb >> (32 - 15)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // III(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[1], 13);
            aaa += I(bbb, ccc, ddd) + _words[1] + 0x5c4dd124;
            aaa = (aaa << 13 | aaa >> (32 - 13)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // III(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[2], 11);
            eee += I(aaa, bbb, ccc) + _words[2] + 0x5c4dd124;
            eee = (eee << 11 | eee >> (32 - 11)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // Parallel Right Round 3
            // HHH(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[15], 9);
            ddd += H(eee, aaa, bbb) + _words[15] + 0x6d703ef3;
            ddd = (ddd << 9 | ddd >> (32 - 9)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // HHH(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[5], 7);
            ccc += H(ddd, eee, aaa) + _words[5] + 0x6d703ef3;
            ccc = (ccc << 7 | ccc >> (32 - 7)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // HHH(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[1], 15);
            bbb += H(ccc, ddd, eee) + _words[1] + 0x6d703ef3;
            bbb = (bbb << 15 | bbb >> (32 - 15)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // HHH(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[3], 11);
            aaa += H(bbb, ccc, ddd) + _words[3] + 0x6d703ef3;
            aaa = (aaa << 11 | aaa >> (32 - 11)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // HHH(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[7], 8);
            eee += H(aaa, bbb, ccc) + _words[7] + 0x6d703ef3;
            eee = (eee << 8 | eee >> (32 - 8)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // HHH(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[14], 6);
            ddd += H(eee, aaa, bbb) + _words[14] + 0x6d703ef3;
            ddd = (ddd << 6 | ddd >> (32 - 6)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // HHH(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[6], 6);
            ccc += H(ddd, eee, aaa) + _words[6] + 0x6d703ef3;
            ccc = (ccc << 6 | ccc >> (32 - 6)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // HHH(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[9], 14);
            bbb += H(ccc, ddd, eee) + _words[9] + 0x6d703ef3;
            bbb = (bbb << 14 | bbb >> (32 - 14)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // HHH(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[11], 12);
            aaa += H(bbb, ccc, ddd) + _words[11] + 0x6d703ef3;
            aaa = (aaa << 12 | aaa >> (32 - 12)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // HHH(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[8], 13);
            eee += H(aaa, bbb, ccc) + _words[8] + 0x6d703ef3;
            eee = (eee << 13 | eee >> (32 - 13)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // HHH(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[12], 5);
            ddd += H(eee, aaa, bbb) + _words[12] + 0x6d703ef3;
            ddd = (ddd << 5 | ddd >> (32 - 5)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // HHH(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[2], 14);
            ccc += H(ddd, eee, aaa) + _words[2] + 0x6d703ef3;
            ccc = (ccc << 14 | ccc >> (32 - 14)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // HHH(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[10], 13);
            bbb += H(ccc, ddd, eee) + _words[10] + 0x6d703ef3;
            bbb = (bbb << 13 | bbb >> (32 - 13)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // HHH(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[0], 13);
            aaa += H(bbb, ccc, ddd) + _words[0] + 0x6d703ef3;
            aaa = (aaa << 13 | aaa >> (32 - 13)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // HHH(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[4], 7);
            eee += H(aaa, bbb, ccc) + _words[4] + 0x6d703ef3;
            eee = (eee << 7 | eee >> (32 - 7)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // HHH(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[13], 5);
            ddd += H(eee, aaa, bbb) + _words[13] + 0x6d703ef3;
            ddd = (ddd << 5 | ddd >> (32 - 5)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // Parallel Right Round 4
            // GGG(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[8], 15);
            ccc += G(ddd, eee, aaa) + _words[8] + 0x7a6d76e9;
            ccc = (ccc << 15 | ccc >> (32 - 15)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // GGG(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[6], 5);
            bbb += G(ccc, ddd, eee) + _words[6] + 0x7a6d76e9;
            bbb = (bbb << 5 | bbb >> (32 - 5)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // GGG(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[4], 8);
            aaa += G(bbb, ccc, ddd) + _words[4] + 0x7a6d76e9;
            aaa = (aaa << 8 | aaa >> (32 - 8)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // GGG(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[1], 11);
            eee += G(aaa, bbb, ccc) + _words[1] + 0x7a6d76e9;
            eee = (eee << 11 | eee >> (32 - 11)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // GGG(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[3], 14);
            ddd += G(eee, aaa, bbb) + _words[3] + 0x7a6d76e9;
            ddd = (ddd << 14 | ddd >> (32 - 14)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // GGG(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[11], 14);
            ccc += G(ddd, eee, aaa) + _words[11] + 0x7a6d76e9;
            ccc = (ccc << 14 | ccc >> (32 - 14)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // GGG(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[15], 6);
            bbb += G(ccc, ddd, eee) + _words[15] + 0x7a6d76e9;
            bbb = (bbb << 6 | bbb >> (32 - 6)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // GGG(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[0], 14);
            aaa += G(bbb, ccc, ddd) + _words[0] + 0x7a6d76e9;
            aaa = (aaa << 14 | aaa >> (32 - 14)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // GGG(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[5], 6);
            eee += G(aaa, bbb, ccc) + _words[5] + 0x7a6d76e9;
            eee = (eee << 6 | eee >> (32 - 6)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // GGG(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[12], 9);
            ddd += G(eee, aaa, bbb) + _words[12] + 0x7a6d76e9;
            ddd = (ddd << 9 | ddd >> (32 - 9)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // GGG(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[2], 12);
            ccc += G(ddd, eee, aaa) + _words[2] + 0x7a6d76e9;
            ccc = (ccc << 12 | ccc >> (32 - 12)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // GGG(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[13], 9);
            bbb += G(ccc, ddd, eee) + _words[13] + 0x7a6d76e9;
            bbb = (bbb << 9 | bbb >> (32 - 9)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // GGG(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[9], 12);
            aaa += G(bbb, ccc, ddd) + _words[9] + 0x7a6d76e9;
            aaa = (aaa << 12 | aaa >> (32 - 12)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // GGG(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[7], 5);
            eee += G(aaa, bbb, ccc) + _words[7] + 0x7a6d76e9;
            eee = (eee << 5 | eee >> (32 - 5)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // GGG(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[10], 15);
            ddd += G(eee, aaa, bbb) + _words[10] + 0x7a6d76e9;
            ddd = (ddd << 15 | ddd >> (32 - 15)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // GGG(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[14], 8);
            ccc += G(ddd, eee, aaa) + _words[14] + 0x7a6d76e9;
            ccc = (ccc << 8 | ccc >> (32 - 8)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // Parallel Right Round 5
            // FFF(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[12], 8);
            bbb += F(ccc, ddd, eee) + _words[12];
            bbb = (bbb << 8 | bbb >> (32 - 8)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // FFF(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[15], 5);
            aaa += F(bbb, ccc, ddd) + _words[15];
            aaa = (aaa << 5 | aaa >> (32 - 5)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // FFF(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[10], 12);
            eee += F(aaa, bbb, ccc) + _words[10];
            eee = (eee << 12 | eee >> (32 - 12)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // FFF(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[4], 9);
            ddd += F(eee, aaa, bbb) + _words[4];
            ddd = (ddd << 9 | ddd >> (32 - 9)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // FFF(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[1], 12);
            ccc += F(ddd, eee, aaa) + _words[1];
            ccc = (ccc << 12 | ccc >> (32 - 12)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // FFF(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[5], 5);
            bbb += F(ccc, ddd, eee) + _words[5];
            bbb = (bbb << 5 | bbb >> (32 - 5)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // FFF(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[8], 14);
            aaa += F(bbb, ccc, ddd) + _words[8];
            aaa = (aaa << 14 | aaa >> (32 - 14)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // FFF(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[7], 6);
            eee += F(aaa, bbb, ccc) + _words[7];
            eee = (eee << 6 | eee >> (32 - 6)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // FFF(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[6], 8);
            ddd += F(eee, aaa, bbb) + _words[6];
            ddd = (ddd << 8 | ddd >> (32 - 8)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // FFF(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[2], 13);
            ccc += F(ddd, eee, aaa) + _words[2];
            ccc = (ccc << 13 | ccc >> (32 - 13)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // FFF(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[13], 6);
            bbb += F(ccc, ddd, eee) + _words[13];
            bbb = (bbb << 6 | bbb >> (32 - 6)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));

            // FFF(ref aaa, ref bbb, ref ccc, ref ddd, ref eee, _words[14], 5);
            aaa += F(bbb, ccc, ddd) + _words[14];
            aaa = (aaa << 5 | aaa >> (32 - 5)) + eee;
            ccc = (ccc << 10 | ccc >> (32 - 10));

            // FFF(ref eee, ref aaa, ref bbb, ref ccc, ref ddd, _words[0], 15);
            eee += F(aaa, bbb, ccc) + _words[0];
            eee = (eee << 15 | eee >> (32 - 15)) + ddd;
            bbb = (bbb << 10 | bbb >> (32 - 10));

            // FFF(ref ddd, ref eee, ref aaa, ref bbb, ref ccc, _words[3], 13);
            ddd += F(eee, aaa, bbb) + _words[3];
            ddd = (ddd << 13 | ddd >> (32 - 13)) + ccc;
            aaa = (aaa << 10 | aaa >> (32 - 10));

            // FFF(ref ccc, ref ddd, ref eee, ref aaa, ref bbb, _words[9], 11);
            ccc += F(ddd, eee, aaa) + _words[9];
            ccc = (ccc << 11 | ccc >> (32 - 11)) + bbb;
            eee = (eee << 10 | eee >> (32 - 10));

            // FFF(ref bbb, ref ccc, ref ddd, ref eee, ref aaa, _words[11], 11);
            bbb += F(ccc, ddd, eee) + _words[11];
            bbb = (bbb << 11 | bbb >> (32 - 11)) + aaa;
            ddd = (ddd << 10 | ddd >> (32 - 10));
        }

        #endregion Methods
    }
}
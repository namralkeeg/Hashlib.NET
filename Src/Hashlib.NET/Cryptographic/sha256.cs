using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// A SHA-2 256-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks> https://en.wikipedia.org/wiki/SHA-2 </remarks>
    public class SHA256 : HashAlgorithm
    {
        #region Fields

        // Split into 64 byte blocks (=> 512 bits)
        protected const int _BlockSize = 64; // 512 / 8

        // Hash is 20 bytes long
        protected const int _HashBytes = 32;

        // Hash is 160 bits long
        protected const int _HashValuesCount = 8; // 20 / 4

        // First 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        protected static readonly uint[] _K;

        protected readonly byte[] _buffer;
        protected readonly uint[] _shaState;

        // Data represented as 16x 32-bit words
        protected readonly uint[] _words;

        protected int _bufferSize;
        protected long _byteCount;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Sets the initial static values of a <see cref="SHA256"/> class.
        /// </summary>
        static SHA256()
        {
            _K = new uint[]
            {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };
        }

        /// <summary>
        /// Sets the initial values of a <see cref="SHA256"/> class.
        /// </summary>
        public SHA256()
        {
            _buffer = new byte[_BlockSize];
            _shaState = new uint[_HashValuesCount];
            _words = new uint[64];
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <inheritdoc/>
        public override int HashSize => 256;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="SHA256"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="SHA256"/> class.</returns>
        public static new SHA256 Create()
        {
            return Create(typeof(SHA256).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="SHA256"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SHA256"/> class.</returns>
        public static new SHA256 Create(string hashName)
        {
            return (SHA256)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);

            // According to RFC 1321
            _shaState[0] = 0x6a09e667;
            _shaState[1] = 0xbb67ae85;
            _shaState[2] = 0x3c6ef372;
            _shaState[3] = 0xa54ff53a;
            _shaState[4] = 0x510e527f;
            _shaState[5] = 0x9b05688c;
            _shaState[6] = 0x1f83d9ab;
            _shaState[7] = 0x5be0cd19;
        }

        protected static uint F1(uint e, uint f, uint g)
        {
            // Sigma1(e) + Ch(e, f, g);
            return unchecked((e.Ror(6) ^ e.Ror(11) ^ e.Ror(25)) + ((e & f) ^ ((~e) & g)));
        }

        protected static uint F2(uint a, uint b, uint c)
        {
            // Sigma0(a) + Maj(a, b, c); // Maj Originally (a & b) ^ (a & c) ^ (b & c)
            return unchecked((a.Ror(2) ^ a.Ror(13) ^ a.Ror(22)) + (((a | b) & c) | (a & b))); 
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
            Array.Copy(_shaState, oldHash, _shaState.Length);

            // Process the remaining bytes.
            ProcessBuffer();

            // Convert from Big-Endian to bytes.
            byte[] hash = new byte[_HashBytes];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount; i++, hashIndex += 4)
            {
                hash[hashIndex + 0] = (byte)(_shaState[i] >> 24);
                hash[hashIndex + 1] = (byte)(_shaState[i] >> 16);
                hash[hashIndex + 2] = (byte)(_shaState[i] >> 08);
                hash[hashIndex + 3] = (byte)(_shaState[i] >> 00);
            }

            // Restore the old hash.
            Array.Copy(oldHash, _shaState, oldHash.Length);

            return hash;
        }

        /// <summary>
        /// The core SHA256 hashing algorithm. It processes 64 byte blocks at a time.
        /// </summary>
        /// <param name="block">The array of data to process.</param>
        /// <param name="startIndex">The index into the array to start at.</param>
        protected void ProcessBlock(byte[] block, int startIndex)
        {
            // get last hash
            uint a = _shaState[0];
            uint b = _shaState[1];
            uint c = _shaState[2];
            uint d = _shaState[3];
            uint e = _shaState[4];
            uint f = _shaState[5];
            uint g = _shaState[6];
            uint h = _shaState[7];

            int current = startIndex;
            // Copy a 64 byte chunk into first 16 words w[0..15] of the message schedule array.
            for (int j = 0; j < 16; j++, current += 4)
            {
                // Convert to Big-Endian
                _words[j] = ToUInt32BE(block, current);
            }

            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array.
            for (int i = 16; i < 64; i++)
            {
                _words[i] = _words[i - 16] +
                    (_words[i - 15].Ror(7) ^ _words[i - 15].Ror(18) ^ (_words[i - 15] >> 3)) +
                    _words[i - 7] +
                    (_words[i - 2].Ror(17) ^ _words[i - 2].Ror(19) ^ (_words[i - 2] >> 10));
            }

            // Temps
            uint x, y;

            // First round
            x = h + F1(e, f, g) + _K[00] + _words[00]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[01] + _words[01]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[02] + _words[02]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[03] + _words[03]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[04] + _words[04]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[05] + _words[05]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[06] + _words[06]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[07] + _words[07]; y = F2(b, c, d); e += x; a = x + y;

            // Secound round
            x = h + F1(e, f, g) + _K[08] + _words[08]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[09] + _words[09]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[10] + _words[10]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[11] + _words[11]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[12] + _words[12]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[13] + _words[13]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[14] + _words[14]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[15] + _words[15]; y = F2(b, c, d); e += x; a = x + y;

            // Third round
            x = h + F1(e, f, g) + _K[16] + _words[16]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[17] + _words[17]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[18] + _words[18]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[19] + _words[19]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[20] + _words[20]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[21] + _words[21]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[22] + _words[22]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[23] + _words[23]; y = F2(b, c, d); e += x; a = x + y;

            // Fourth round
            x = h + F1(e, f, g) + _K[24] + _words[24]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[25] + _words[25]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[26] + _words[26]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[27] + _words[27]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[28] + _words[28]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[29] + _words[29]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[30] + _words[30]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[31] + _words[31]; y = F2(b, c, d); e += x; a = x + y;

            // Fifth round
            x = h + F1(e, f, g) + _K[32] + _words[32]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[33] + _words[33]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[34] + _words[34]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[35] + _words[35]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[36] + _words[36]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[37] + _words[37]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[38] + _words[38]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[39] + _words[39]; y = F2(b, c, d); e += x; a = x + y;

            // Sixth round
            x = h + F1(e, f, g) + _K[40] + _words[40]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[41] + _words[41]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[42] + _words[42]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[43] + _words[43]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[44] + _words[44]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[45] + _words[45]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[46] + _words[46]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[47] + _words[47]; y = F2(b, c, d); e += x; a = x + y;

            // Seventh round
            x = h + F1(e, f, g) + _K[48] + _words[48]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[49] + _words[49]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[50] + _words[50]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[51] + _words[51]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[52] + _words[52]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[53] + _words[53]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[54] + _words[54]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[55] + _words[55]; y = F2(b, c, d); e += x; a = x + y;

            // Eigth round
            x = h + F1(e, f, g) + _K[56] + _words[56]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + _K[57] + _words[57]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + _K[58] + _words[58]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + _K[59] + _words[59]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + _K[60] + _words[60]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + _K[61] + _words[61]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + _K[62] + _words[62]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + _K[63] + _words[63]; y = F2(b, c, d); e += x; a = x + y;

            // Update hash
            _shaState[0] += a;
            _shaState[1] += b;
            _shaState[2] += c;
            _shaState[3] += d;
            _shaState[4] += e;
            _shaState[5] += f;
            _shaState[6] += g;
            _shaState[7] += h;
        }

        protected void ProcessBuffer()
        {
            // The input bytes are considered as bits strings, where the first bit is the most
            // significant bit of the byte

            // Append "1" bit to message
            // Append "0" bits until message length in bit mod 512 is 448
            // Append length as 64 bit integer

            // Number of bits
            uint paddedLength = (uint)_bufferSize * 8;

            // Plus one bit set to 1 (always appended)
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

            // Convert from bits to bytes
            paddedLength /= 8;

            // Only needed if additional data flows over into a second block
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

            int i;
            for (i = _bufferSize + 1; i < _BlockSize; i++)
            {
                _buffer[i] = 0;
            }
            for (; i < paddedLength; i++)
            {
                extra[i - _BlockSize] = 0;
            }

            // Add message length in bits as 64 bit number
            ulong msgBits = 8 * (ulong)(_byteCount + _bufferSize);
            
            // Find right position
            uint addLength;
            if (paddedLength < _BlockSize)
            {
                addLength = paddedLength;

                // Must be big endian
                _buffer[addLength++] = (byte)((msgBits >> 56) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 48) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 40) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 32) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 24) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 16) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 08) & 0xFF);
                _buffer[addLength++] = (byte)((msgBits >> 00) & 0xFF);
            }
            else
            {
                addLength = paddedLength - _BlockSize;

                // Must be big endian
                extra[addLength++] = (byte)((msgBits >> 56) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 48) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 40) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 32) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 24) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 16) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 08) & 0xFF);
                extra[addLength++] = (byte)((msgBits >> 00) & 0xFF);
            }

            // Process block
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
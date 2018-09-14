using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;
using static Hashlib.NET.Common.BitConverterEndian;

namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// A SHA-2 512-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks> https://en.wikipedia.org/wiki/SHA-2 </remarks>
    public class SHA512 : HashAlgorithm
    {
        #region Fields

        // Split into 128 byte blocks (=> 1024 bits)
        protected const int _BlockSize = 128; // 1024 / 8

        // Hash is 64 bytes long
        protected const int _HashBytes = 64;

        // Hash is 512 bits long
        protected const int _HashValuesCount = 8; // 64 / 8

        protected readonly byte[] _buffer;
        protected readonly ulong[] _shaState;

        // Data represented as 16x 64-bit words
        protected readonly ulong[] _words;

        protected int _bufferSize;
        protected long _byteCount;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Sets the initial static values of a <see cref="SHA512"/> class.
        /// </summary>
        public SHA512()
        {
            _buffer = new byte[_BlockSize];
            _shaState = new ulong[_HashValuesCount];
            _words = new ulong[80];
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <inheritdoc/>
        public override int HashSize => 512;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="SHA512"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="SHA512"/> class.</returns>
        public static new SHA512 Create()
        {
            return Create(typeof(SHA512).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="SHA512"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SHA512"/> class.</returns>
        public static new SHA512 Create(string hashName)
        {
            return (SHA512)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="SHA512"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
            Array.Clear(_words, 0, _words.Length);

            // According to RFC 1321
            _shaState[0] = 0x6a09e667f3bcc908;
            _shaState[1] = 0xbb67ae8584caa73b;
            _shaState[2] = 0x3c6ef372fe94f82b;
            _shaState[3] = 0xa54ff53a5f1d36f1;
            _shaState[4] = 0x510e527fade682d1;
            _shaState[5] = 0x9b05688c2b3e6c1f;
            _shaState[6] = 0x1f83d9abfb41bd6b;
            _shaState[7] = 0x5be0cd19137e2179;
        }

        protected static ulong F1(ulong e, ulong f, ulong g)
        {
            // S1 = (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
            // Ch = (e and f) xor ((not e) and g)
            // F1 = S1(e) + Ch(e, f, g);
            return unchecked((e.Ror(14) ^ e.Ror(18) ^ e.Ror(41)) + ((e & f) ^ ((~e) & g)));
        }

        protected static ulong F2(ulong a, ulong b, ulong c)
        {
            // S0 = (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            // Maj = (((a | b) & c) | (a & b)) // Maj Originally (a & b) ^ (a & c) ^ (b & c)
            // F2 = S0(a) + Maj(a, b, c);
            return unchecked((a.Ror(28) ^ a.Ror(34) ^ a.Ror(39)) + (((a | b) & c) | (a & b)));
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
            ulong[] oldHash = new ulong[_HashValuesCount];
            Array.Copy(_shaState, oldHash, _shaState.Length);

            // Process the remaining bytes.
            ProcessBuffer();

            // Convert from Big-Endian to bytes.
            byte[] hash = new byte[_HashBytes];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount; i++, hashIndex += 8)
            {
                SetBytesBE(_shaState[i], hash, hashIndex);
            }

            // Restore the old hash.
            Array.Copy(oldHash, _shaState, oldHash.Length);

            return hash;
        }

        /// <summary>
        /// The core SHA512 hashing algorithm. It processes 128 byte blocks at a time.
        /// </summary>
        /// <param name="block">The array of data to process.</param>
        /// <param name="startIndex">The index into the array to start at.</param>
        protected void ProcessBlock(byte[] block, int startIndex)
        {
            // get last hash
            ulong a = _shaState[0];
            ulong b = _shaState[1];
            ulong c = _shaState[2];
            ulong d = _shaState[3];
            ulong e = _shaState[4];
            ulong f = _shaState[5];
            ulong g = _shaState[6];
            ulong h = _shaState[7];

            // Copy a 128 byte chunk into first 16 words w[0..15] of the message schedule array.
            for (int j = 0, current = startIndex; j < 16; j++, current += 8)
            {
                // Convert to Big-Endian
                _words[j] = ToUInt64BE(block, current);
            }

            // Extend the first 16 words into the remaining 64 words w[16..80] of the message schedule array.
            for (int i = 16; i < 80; i++)
            {
                // s0 = (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
                // s1 = (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i- 2] rightshift 6)
                // words[i] = w[i-16] + s0 + w[i-7] + s1
                unchecked
                {
                    _words[i] = 
                        (_words[i - 16]) +
                        (_words[i - 15].Ror(1) ^ _words[i - 15].Ror(8) ^ (_words[i - 15] >> 7)) +
                        (_words[i - 07]) +
                        (_words[i - 02].Ror(19) ^ _words[i - 2].Ror(61) ^ (_words[i - 2] >> 6));
                }
            }

            // Temps
            ulong x, y;

            // First round
            x = h + F1(e, f, g) + 0x428a2f98d728ae22 + _words[00]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x7137449123ef65cd + _words[01]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xb5c0fbcfec4d3b2f + _words[02]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xe9b5dba58189dbbc + _words[03]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x3956c25bf348b538 + _words[04]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x59f111f1b605d019 + _words[05]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x923f82a4af194f9b + _words[06]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0xab1c5ed5da6d8118 + _words[07]; y = F2(b, c, d); e += x; a = x + y;

            // Secound round
            x = h + F1(e, f, g) + 0xd807aa98a3030242 + _words[08]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x12835b0145706fbe + _words[09]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x243185be4ee4b28c + _words[10]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x550c7dc3d5ffb4e2 + _words[11]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x72be5d74f27b896f + _words[12]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x80deb1fe3b1696b1 + _words[13]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x9bdc06a725c71235 + _words[14]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0xc19bf174cf692694 + _words[15]; y = F2(b, c, d); e += x; a = x + y;

            // Third round
            x = h + F1(e, f, g) + 0xe49b69c19ef14ad2 + _words[16]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xefbe4786384f25e3 + _words[17]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x0fc19dc68b8cd5b5 + _words[18]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x240ca1cc77ac9c65 + _words[19]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x2de92c6f592b0275 + _words[20]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x4a7484aa6ea6e483 + _words[21]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x5cb0a9dcbd41fbd4 + _words[22]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x76f988da831153b5 + _words[23]; y = F2(b, c, d); e += x; a = x + y;

            // Fourth round
            x = h + F1(e, f, g) + 0x983e5152ee66dfab + _words[24]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xa831c66d2db43210 + _words[25]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xb00327c898fb213f + _words[26]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xbf597fc7beef0ee4 + _words[27]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0xc6e00bf33da88fc2 + _words[28]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0xd5a79147930aa725 + _words[29]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x06ca6351e003826f + _words[30]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x142929670a0e6e70 + _words[31]; y = F2(b, c, d); e += x; a = x + y;

            // Fifth round
            x = h + F1(e, f, g) + 0x27b70a8546d22ffc + _words[32]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x2e1b21385c26c926 + _words[33]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x4d2c6dfc5ac42aed + _words[34]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x53380d139d95b3df + _words[35]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x650a73548baf63de + _words[36]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x766a0abb3c77b2a8 + _words[37]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x81c2c92e47edaee6 + _words[38]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x92722c851482353b + _words[39]; y = F2(b, c, d); e += x; a = x + y;

            // Sixth round
            x = h + F1(e, f, g) + 0xa2bfe8a14cf10364 + _words[40]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xa81a664bbc423001 + _words[41]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xc24b8b70d0f89791 + _words[42]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xc76c51a30654be30 + _words[43]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0xd192e819d6ef5218 + _words[44]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0xd69906245565a910 + _words[45]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0xf40e35855771202a + _words[46]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x106aa07032bbd1b8 + _words[47]; y = F2(b, c, d); e += x; a = x + y;

            // Seventh round
            x = h + F1(e, f, g) + 0x19a4c116b8d2d0c8 + _words[48]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x1e376c085141ab53 + _words[49]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x2748774cdf8eeb99 + _words[50]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x34b0bcb5e19b48a8 + _words[51]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x391c0cb3c5c95a63 + _words[52]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x4ed8aa4ae3418acb + _words[53]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x5b9cca4f7763e373 + _words[54]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x682e6ff3d6b2b8a3 + _words[55]; y = F2(b, c, d); e += x; a = x + y;

            // Eigth round
            x = h + F1(e, f, g) + 0x748f82ee5defb2fc + _words[56]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x78a5636f43172f60 + _words[57]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x84c87814a1f0ab72 + _words[58]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x8cc702081a6439ec + _words[59]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x90befffa23631e28 + _words[60]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0xa4506cebde82bde9 + _words[61]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0xbef9a3f7b2c67915 + _words[62]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0xc67178f2e372532b + _words[63]; y = F2(b, c, d); e += x; a = x + y;

            // Ninth round
            x = h + F1(e, f, g) + 0xca273eceea26619c + _words[64]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0xd186b8c721c0c207 + _words[65]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0xeada7dd6cde0eb1e + _words[66]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0xf57d4f7fee6ed178 + _words[67]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x06f067aa72176fba + _words[68]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x0a637dc5a2c898a6 + _words[69]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x113f9804bef90dae + _words[70]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x1b710b35131c471b + _words[71]; y = F2(b, c, d); e += x; a = x + y;

            // Tenth round
            x = h + F1(e, f, g) + 0x28db77f523047d84 + _words[72]; y = F2(a, b, c); d += x; h = x + y;
            x = g + F1(d, e, f) + 0x32caab7b40c72493 + _words[73]; y = F2(h, a, b); c += x; g = x + y;
            x = f + F1(c, d, e) + 0x3c9ebe0a15c9bebc + _words[74]; y = F2(g, h, a); b += x; f = x + y;
            x = e + F1(b, c, d) + 0x431d67c49c100d4c + _words[75]; y = F2(f, g, h); a += x; e = x + y;
            x = d + F1(a, b, c) + 0x4cc5d4becb3e42b6 + _words[76]; y = F2(e, f, g); h += x; d = x + y;
            x = c + F1(h, a, b) + 0x597f299cfc657e2a + _words[77]; y = F2(d, e, f); g += x; c = x + y;
            x = b + F1(g, h, a) + 0x5fcb6fab3ad6faec + _words[78]; y = F2(c, d, e); f += x; b = x + y;
            x = a + F1(f, g, h) + 0x6c44198c4a475817 + _words[79]; y = F2(b, c, d); e += x; a = x + y;

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

            // The number of bits must be (numBits % 1024) = 896
            uint lowerBits = paddedLength & 1016;
            if (lowerBits <= 896)
            {
                paddedLength += 896 - lowerBits;
            }
            else
            {
                paddedLength += 1024 + 896 - lowerBits;
            }

            // Convert from bits to bytes
            paddedLength /= 8;

            // Only needed if additional data flows over into a second block
            var extra = new byte[_BlockSize];

            // Append a "1" bit, 128 => binary 10000000
            if (_bufferSize < _BlockSize)
            {
                _buffer[_bufferSize] = 0x80; // 128
            }
            else
            {
                extra[0] = 0x80; // 128
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

            // Add message length in bits as 128 bit number
            ulong msgBits = 8 * (ulong)(_byteCount + _bufferSize);

            // Find right position
            uint addLength;
            if (paddedLength < _BlockSize)
            {
                // Skip the first 64 bits of the number until there's an UInt128.
                addLength = paddedLength + 8;

                // Must be big endian
                _buffer[addLength++] = (byte)(msgBits >> 56);
                _buffer[addLength++] = (byte)(msgBits >> 48);
                _buffer[addLength++] = (byte)(msgBits >> 40);
                _buffer[addLength++] = (byte)(msgBits >> 32);
                _buffer[addLength++] = (byte)(msgBits >> 24);
                _buffer[addLength++] = (byte)(msgBits >> 16);
                _buffer[addLength++] = (byte)(msgBits >> 08);
                _buffer[addLength++] = (byte)(msgBits >> 00);
            }
            else
            {
                // Skip the first 64 bits of the number until there's an UInt128.
                addLength = paddedLength - _BlockSize + 8;

                // Must be big endian
                extra[addLength++] = (byte)(msgBits >> 56);
                extra[addLength++] = (byte)(msgBits >> 48);
                extra[addLength++] = (byte)(msgBits >> 40);
                extra[addLength++] = (byte)(msgBits >> 32);
                extra[addLength++] = (byte)(msgBits >> 24);
                extra[addLength++] = (byte)(msgBits >> 16);
                extra[addLength++] = (byte)(msgBits >> 08);
                extra[addLength++] = (byte)(msgBits >> 00);
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
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

namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// A SHA-2 224-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// SHA-224 is identical to SHA-256, except that the initial hash values h0 through h7 are
    /// different, and the output is constructed by omitting h7.
    /// </remarks>
    public sealed class SHA224 : SHA256
    {
        #region Constructors

        /// <summary>
        /// Sets the initial values of a <see cref="SHA224"/> class.
        /// </summary>
        public SHA224()
        { }

        #endregion Constructors

        #region Properties

        /// <inheritdoc/>
        public override int HashSize => 224;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="SHA224"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="SHA224"/> class.</returns>
        public static new SHA224 Create()
        {
            return Create(typeof(SHA224).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="SHA224"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SHA224"/> class.</returns>
        public static new SHA224 Create(string hashName)
        {
            return (SHA224)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        ///  Sets the initial values of a <see cref="SHA224"/> class.
        /// </summary>
        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);

            // According to RFC 1321.
            // The second 32 bits of the fractional parts of the square roots
            // of the 9th through 16th primes 23..53)
            _shaState[0] = 0xc1059ed8;
            _shaState[1] = 0x367cd507;
            _shaState[2] = 0x3070dd17;
            _shaState[3] = 0xf70e5939;
            _shaState[4] = 0xffc00b31;
            _shaState[5] = 0x68581511;
            _shaState[6] = 0x64f98fa7;
            _shaState[7] = 0xbefa4fa4;
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
            // For Sha 224 the output is constructed by omitting h7. (0 to 6)
            byte[] hash = new byte[_HashBytes - sizeof(uint)];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount - 1; i++, hashIndex += 4)
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

        #endregion Methods
    }
}
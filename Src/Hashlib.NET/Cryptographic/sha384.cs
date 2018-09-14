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
    /// A SHA-2 384-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// SHA-384 is identical to SHA-512, except that:
    /// The initial hash values h0 through h7 are different(taken from the 9th through 16th primes), and
    /// the output is constructed by omitting h6 and h7.
    /// </remarks>
    public class SHA384 : SHA512
    {
        #region Constructors

        /// <summary>
        /// Sets the initial static values of a <see cref="SHA384"/> class.
        /// </summary>
        public SHA384()
        { }

        #endregion Constructors

        #region Properties

        /// <inheritdoc/>
        public override int HashSize => 384;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="SHA384"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="SHA384"/> class.</returns>
        public static new SHA384 Create()
        {
            return Create(typeof(SHA384).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="SHA384"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="SHA384"/> class.</returns>
        public static new SHA384 Create(string hashName)
        {
            return (SHA384)HashAlgorithmFactory.Create(hashName);
        }

        public override void Initialize()
        {
            _byteCount = 0;
            _bufferSize = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
            Array.Clear(_words, 0, _words.Length);

            // According to RFC 1321
            // For SHA384 the initial hash values h0 through h7 are different (taken from the 9th
            // through 16th primes)
            _shaState[0] = 0xcbbb9d5dc1059ed8;
            _shaState[1] = 0x629a292a367cd507;
            _shaState[2] = 0x9159015a3070dd17;
            _shaState[3] = 0x152fecd8f70e5939;
            _shaState[4] = 0x67332667ffc00b31;
            _shaState[5] = 0x8eb44a8768581511;
            _shaState[6] = 0xdb0c2e0d64f98fa7;
            _shaState[7] = 0x47b5481dbefa4fa4;
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            // Save the old hash if the buffer is partially filled.
            ulong[] oldHash = new ulong[_HashValuesCount];
            Array.Copy(_shaState, oldHash, _shaState.Length);

            // Process the remaining bytes.
            ProcessBuffer();

            // For SHA384 the output is constructed by omitting h6 and h7.
            byte[] hash = new byte[_HashBytes - sizeof(ulong) * 2];
            for (int i = 0, hashIndex = 0; i < _HashValuesCount - 2; i++, hashIndex += 8)
            {
                // Convert from Big-Endian to bytes.
                SetBytesBE(_shaState[i], hash, hashIndex);
            }

            // Restore the old hash.
            Array.Copy(oldHash, _shaState, oldHash.Length);

            return hash;
        }

        #endregion Methods
    }
}
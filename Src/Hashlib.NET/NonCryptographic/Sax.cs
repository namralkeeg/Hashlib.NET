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

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A Shift-Add-XOR hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    public sealed class Sax : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultSeed = 0;
        private uint hash;

        #endregion Fields

        #region Constructors

        public Sax()
        {
            HashSizeValue = _BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Sax"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Sax"/> class.</returns>
        public static new Sax Create()
        {
            return Create(typeof(Sax).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Sax"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Sax"/> class.</returns>
        public static new Sax Create(string hashName)
        {
            return (Sax)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Sax"/> class.
        /// </summary>
        public override void Initialize()
        {
            hash = _DefaultSeed;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    hash ^= (hash << 5) + (hash >> 2) + array[i];
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }

        #endregion Methods
    }
}
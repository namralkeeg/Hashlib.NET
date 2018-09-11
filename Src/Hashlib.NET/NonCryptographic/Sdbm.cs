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
    /// A SDBM hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>The algorithm of choice which is used in the open source SDBM project.</remarks>
    public sealed class Sdbm : HashAlgorithm
    {
        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultSeed = 0;
        private uint _hash;

        /// <summary>
        /// Initializes a <see cref="Sdbm"/> class.
        /// </summary>
        public Sdbm()
        {
            HashSizeValue = _BitSize;
            Initialize();
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Sdbm"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Sdbm"/> class.</returns>
        public static new Sdbm Create()
        {
            return Create(typeof(Sdbm).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Sdbm"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Sdbm"/> class.</returns>
        public static new Sdbm Create(string hashName)
        {
            return (Sdbm)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Sdbm"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _DefaultSeed;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    _hash = array[i] + (_hash << 6) + (_hash << 16) - _hash;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(_hash);
        }
    }
}

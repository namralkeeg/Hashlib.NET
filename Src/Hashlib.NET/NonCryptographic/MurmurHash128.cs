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
    /// An abstract base class for the MurmurHash3 128-bit implementation of <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// The <see cref="Create"/> functions return the default implementation of the <see cref="MurmurHash128"/>
    /// for the current platform.
    /// </remarks>
    public abstract class MurmurHash128 : HashAlgorithm
    {
        protected const int _BitSize = 128;
        protected const uint _DefaultSeed = 0;

        protected uint _seed;

        /// <inheritdoc/>
        public override int HashSize => _BitSize;

        /// <summary>
        /// Gets and sets the seed value to use for computing the hash.
        /// </summary>
        public uint Seed
        {
            get => _seed;
            set
            {
                _seed = value;
                Initialize();
            }
        }

        /// <summary>
        /// Creates a new instance of a <see cref="MurmurHash128"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="MurmurHash128"/> class.</returns>
        /// <remarks>
        /// Creates the default <see cref="MurmurHash128"/> underlying implementation for the current platform.
        /// </remarks>
        public static new MurmurHash128 Create()
        {
            if (Environment.Is64BitProcess)
            {
                return Create(typeof(MurmurHash3x64_128).Name);
            }
            else // If 32-bit process.
            {
                return Create(typeof(MurmurHash3x86_128).Name);
            }
        }

        /// <summary>
        /// Creates a new instance of a <see cref="MurmurHash128"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="MurmurHash128"/> class.</returns>
        /// <remarks>
        /// Creates the default <see cref="MurmurHash128"/> underlying implementation for the current platform.
        /// </remarks>
        public static new MurmurHash128 Create(string hashName)
        {
            return (MurmurHash128)HashAlgorithmFactory.Create(hashName);
        }
    }
}
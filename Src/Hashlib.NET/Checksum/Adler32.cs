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

namespace Hashlib.NET.Checksum
{
    /// <summary>
    /// An Adler 32-bit checksum implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// Adler32 is a checksum algorithm invented by Mark Adler. 
    /// https://en.wikipedia.org/wiki/Adler-32
    /// </remarks>
    public sealed class Adler32 : HashAlgorithm
    {
        #region Fields

        private const uint _ModAdler = 65521u;
        private uint _hashA;
        private uint _hashB;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes an <see cref="Adler32"/> class.
        /// </summary>
        public Adler32()
        {
            HashSizeValue = 32;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Adler32"/> class.
        /// </summary>
        /// <returns>A new instance of an <see cref="Adler32"/> class.</returns>
        public static new Adler32 Create()
        {
            return Create(typeof(Adler32).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Adler32"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of an <see cref="Adler32"/> class.</returns>
        public static new Adler32 Create(string hashName)
        {
            return (Adler32)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Initializes an instance of <see cref="Adler32"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hashA = 1;
            _hashB = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null)
            {
                _hashA = 1u;
            }

            if (array.Length == 1)
            {
                _hashA += array[0];
                if (_hashA >= _ModAdler)
                {
                    _hashA -= _ModAdler;
                }

                _hashB += _hashA;
                if (_hashB >= _ModAdler)
                {
                    _hashB -= _ModAdler;
                }
            }
            else
            {
                for (var i = ibStart; i < ibStart + cbSize; i++)
                {
                    unchecked
                    {
                        _hashA = (_hashA + array[i]) % _ModAdler;
                        _hashB = (_hashB + _hashA) % _ModAdler;
                    }
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(((_hashB << 16) | _hashA));
        }

        #endregion Methods
    }
}
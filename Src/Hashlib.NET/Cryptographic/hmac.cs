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
    /// A HMAC keyed hash implementation of the <see cref="KeyedHashAlgorithm"/> class.
    /// </summary>
    /// <typeparam name="T">The hash algorithm type to use for the HMAC.</typeparam>
    public class HMAC<T> : KeyedHashAlgorithm, IKeyedHash
        where T : ICryptographicBlockHash, new()
    {
        #region Fields

        private readonly int _blockSize;
        private T _hashAlgorithm1;
        private T _hashAlgorithm2;
        private bool _hashing = false;

        private byte[] _inner; // PaddedKey ^ {0x36,...,0x36}
        private byte[] _outer; // PaddedKey ^ {0x5C,...,0x5C}

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Sets the initial values of a <see cref="HMAC{T}"/> class.
        /// </summary>
        /// <remarks>The key value is randomly generated.</remarks>
        public HMAC() : this(null)
        { }

        /// <summary>
        /// Sets the initial values of a <see cref="HMAC{T}"/> class.
        /// </summary>
        /// <param name="key">The secret key for <see cref="HMAC{T}"/> encryption.</param>
        /// <remarks>
        /// The key can be any length, but if it is more bytes long than <see cref="T"/> block size
        /// it will be hashed to derive <see cref="T"/> block size key. Therefore, the recommended
        /// size of the secret key is <see cref="T"/> block size.
        /// </remarks>
        public HMAC(byte[] key)
        {
            _hashAlgorithm1 = new T();
            _hashAlgorithm2 = new T();
            _blockSize = _hashAlgorithm1.BlockSize;
            KeyValue = new byte[_blockSize];
            Key = key ?? Utils.GenerateRandomKey(_blockSize);
            HashSizeValue = _hashAlgorithm2.HashSize;
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets or sets the key to use in the hash algorithm.
        /// </summary>
        /// <value>The <see cref="byte"/> array to use as the key in the hash algorithm.</value>
        public override byte[] Key
        {
            get => Utils.CopyArray(KeyValue);
            set
            {
                if (_hashing)
                {
                    throw new CryptographicException("Cannot change key while hashing is in progress.");
                }

                InitializeKey(value);
            }
        }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="HMAC{T}"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="HMAC{T}"/> class.</returns>
        public static new HMAC<T> Create()
        {
            return new HMAC<T>();
        }

        /// <summary>
        /// Disabled for <see cref="HMAC{T}"/> class.
        /// </summary>
        /// <param name="hashName"></param>
        /// <returns></returns>
        public static new HMAC<T> Create(string hashName)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Sets the initial values of a <see cref="HMAC{T}"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hashAlgorithm1.Initialize();
            _hashAlgorithm2.Initialize();
            _hashing = false;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_hashAlgorithm1 != null)
                {
                    ((IDisposable)_hashAlgorithm1).Dispose();
                }

                if (_hashAlgorithm2 != null)
                {
                    ((IDisposable)_hashAlgorithm2).Dispose();
                }

                if (_inner != null)
                {
                    Array.Clear(_inner, 0, _inner.Length);
                }

                if (_outer != null)
                {
                    Array.Clear(_outer, 0, _outer.Length);
                }
            }

            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (_hashing == false)
            {
                _hashAlgorithm1.TransformBlock(_inner, 0, _inner.Length, _inner, 0);
                _hashing = true;
            }

            _hashAlgorithm1.TransformBlock(array, ibStart, cbSize, array, ibStart);
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            if (_hashing == false)
            {
                _hashAlgorithm1.TransformBlock(_inner, 0, _inner.Length, _inner, 0);
                _hashing = true;
            }

            // finalize the original hash
            _hashAlgorithm1.TransformFinalBlock(Utils.EmptyArray<byte>.Value, 0, 0);
            byte[] hashValue1 = _hashAlgorithm1.Hash;

            // write the outer array
            _hashAlgorithm2.TransformBlock(_outer, 0, _outer.Length, _outer, 0);

            // write the inner hash and finalize the hash
            _hashAlgorithm2.TransformBlock(hashValue1, 0, hashValue1.Length, hashValue1, 0);
            _hashAlgorithm2.TransformFinalBlock(Utils.EmptyArray<byte>.Value, 0, 0);
            _hashing = false;

            return _hashAlgorithm2.Hash;
        }

        /// <summary>
        /// Initializes the key and the initial values of the inner and outter computation buffers.
        /// </summary>
        /// <param name="key">The key to use in the hash algorithm.</param>
        /// <remarks>
        /// When the key value changes, the initial values of the inner and outter computation buffers
        /// need to be changed as well.
        /// </remarks>
        private void InitializeKey(byte[] key)
        {
            // Clear and null the buffers for security.
            if (_inner != null)
            {
                Array.Clear(_inner, 0, _inner.Length);
                _inner = null;
                _inner = new byte[_blockSize];
            }
            if (_outer != null)
            {
                Array.Clear(_outer, 0, _outer.Length);
                _outer = null;
                _outer = new byte[_blockSize];
            }

            // If the key is larger than the blocksize, adjust to match.
            if (key.Length > _blockSize)
            {
                // No need to call Initialize, ComputeHash will do it for us
                KeyValue = _hashAlgorithm1.ComputeHash(key);
            }
            else
            {
                Array.Clear(KeyValue, 0, KeyValue.Length);
                Array.Copy(key, 0, KeyValue, 0, key.Length);
            }

            Utils.Fill(_inner, (byte)0x36);
            Utils.Fill(_outer, (byte)0x5C);

            for (int i = 0; i < KeyValue.Length; i++)
            {
                _inner[i] ^= KeyValue[i];
                _outer[i] ^= KeyValue[i];
            }
        }

        #endregion Methods
    }
}
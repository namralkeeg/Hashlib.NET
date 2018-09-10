using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A DEK hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>An algorithm proposed by Donald E. Knuth in The Art Of Computer Programming Volume 3.</remarks>
    public sealed class Dek : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultSeed = 0;
        private uint _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Dek"/> class.
        /// </summary>
        public Dek()
        {
            HashSizeValue = _BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Dek"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Dek"/> class.</returns>
        public static new Dek Create()
        {
            return Create(typeof(Dek).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Dek"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Dek"/> class.</returns>
        public static new Dek Create(string hashName)
        {
            return (Dek)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Dek"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _DefaultSeed;
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (_hash == 0)
            {
                _hash = (uint)cbSize;
            }

            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                _hash = ((_hash << 5) ^ (_hash >> 27)) ^ array[i];
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>The computed hash as a byte array.</returns>
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(_hash);
        }

        #endregion Methods
    }
}
using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A JS hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>A bitwise hash algorithm written by Justin Sobel</remarks>
    public sealed class Js : HashAlgorithm
    {
        #region Fields

        private const int _BitSize = sizeof(uint) * 8;
        private const uint _DefaultSeed = 1315423911u;
        private uint _hash;

        #endregion Fields

        #region Constructors
        /// <summary>
        /// Initializes a <see cref="Js"/> class.
        /// </summary>
        public Js()
        {
            HashSizeValue = _BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Js"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Js"/> class.</returns>
        public static new Js Create()
        {
            return Create(typeof(Js).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Js"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Js"/> class.</returns>
        public static new Js Create(string hashName)
        {
            return (Js)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Js"/> class.
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
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    _hash ^= ((_hash << 5) + array[i] + (_hash >> 2));
                }
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
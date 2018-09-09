using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A BKDR hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// This hash function comes from Brian Kernighan and Dennis Ritchie's book "The C Programming Language".
    /// </remarks>
    public sealed class Bkdr : HashAlgorithm
    {
        #region Fields

        private const uint _DefaultSeed = 131u;
        private uint _hash;
        private uint _seed;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Bkdr"/> class.
        /// </summary>
        public Bkdr()
        {
            /// 31 131 1313 13131 131313 etc..
            _seed = _DefaultSeed;
            HashSizeValue = 32;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the seed value.
        /// </summary>
        /// <value>Should be in a pattern of 31's, 31 131 1313 13131 131313 etc..</value>
        public uint Seed { get => _seed; set => _seed = value; }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Bkdr"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Bkdr"/> class.</returns>
        public static new Bkdr Create()
        {
            return Create(typeof(Bkdr).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Bkdr"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Bkdr"/> class.</returns>
        public static new Bkdr Create(string hashName)
        {
            return (Bkdr)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Bkdr"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = 0;
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (int i = ibStart; i < ibStart + cbSize; i++)
            {
                _hash = unchecked((_hash * _seed) + array[i]);
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
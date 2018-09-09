using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// An Arash Partow hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>See http://www.partow.net/programming/hashfunctions/ for details.</remarks>
    public sealed class Ap : HashAlgorithm
    {
        #region Fields

        private const uint _seed = 0xAAAAAAAAu;
        private uint _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes an <see cref="Ap"/> class.
        /// </summary>
        public Ap()
        {
            HashSizeValue = 32;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of an <see cref="Ap"/> class.
        /// </summary>
        /// <returns>A new instance of an <see cref="Ap"/> class.</returns>
        public static new Ap Create()
        {
            return Create(typeof(Ap).Name);
        }

        /// <summary>
        /// Creates a new instance of an <see cref="Ap"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of an <see cref="Ap"/> class.</returns>
        public static new Ap Create(string hashName)
        {
            return (Ap)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of an <see cref="Ap"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _seed;
            if ((HashValue != null) && (HashValue.Length > 0))
            {
                Array.Clear(HashValue, 0, HashValue.Length);
            }
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
                if ((i & 0x01) == 0)
                {
                    _hash ^= (_hash << 7) ^ array[i] ^ (_hash >> 3);
                }
                else
                {
                    _hash ^= ~((_hash << 11) ^ array[i] ^ (_hash >> 5));
                }
                //_hash ^= ((i & 0x01) == 0) ? ((_hash <<  7) ^ array[i] ^ (_hash >> 3)) :
                //                            ~((_hash << 11) ^ array[i] ^ (_hash >> 5));
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
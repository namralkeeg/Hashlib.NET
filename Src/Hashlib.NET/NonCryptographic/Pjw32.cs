using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A PJW 32-bit hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// This algorithm is based on work by Peter J. Weinberger of AT&T Bell Labs.
    /// https://en.wikipedia.org/wiki/PJW_hash_function
    /// </remarks>
    public sealed class Pjw32 : HashAlgorithm
    {
        #region Fields

        private const uint _BitSize = 32;
        private const uint _DefaultSeed = 0;
        private const uint _HighBits = 0xFFFFFFFF << (int)(_BitSize - _OneEighth);
        private const uint _OneEighth = (_BitSize / 8);
        private const uint _ThreeQuarters = ((_BitSize * 3) / 4);
        private uint _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Pjw32"/> class.
        /// </summary>
        public Pjw32()
        {
            HashSizeValue = (int)_BitSize;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Pjw32"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Pjw32"/> class.</returns>
        public static new Pjw32 Create()
        {
            return Create(typeof(Pjw32).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Pjw32"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Pjw32"/> class.</returns>
        public static new Pjw32 Create(string hashName)
        {
            return (Pjw32)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Pjw32"/> class.
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
            uint test = 0;
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    _hash = (_hash << (int)_OneEighth) + array[i];

                    test = _hash & _HighBits;
                    if (test != 0)
                    {
                        _hash = (_hash ^ (test >> (int)_ThreeQuarters)) & (~_HighBits);
                    }
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
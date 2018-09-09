using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// An FNV-1a implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>See a detailed description at http://www.isthe.com/chongo/tech/comp/fnv/ </remarks>
    public sealed class Fnv1a : Fnv1
    {
        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Fnv1a"/> class.
        /// </summary>
        public Fnv1a() : base()
        { }

        /// <summary>
        /// Initializes a <see cref="Fnv1a"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size of the FNV-1 hash to generate.</param>
        public Fnv1a(int bitSize) : base(bitSize)
        { }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Fnv1a"/> class.
        /// </summary>
        /// <returns>A new instance of an <see cref="Fnv1a"/> class.</returns>
        public static new Fnv1a Create()
        {
            return Create(typeof(Fnv1a).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Fnv1a"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of an <see cref="Fnv1a"/> class.</returns>
        public static new Fnv1a Create(string hashName)
        {
            return (Fnv1a)HashAlgorithmFactory.Create(hashName);
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
                    _hash = (_hash ^ array[i]) * _fnvPrime % _fnvMod;
                }
            }
        }

        #endregion Methods
    }
}
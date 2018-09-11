using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// A RS hash implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>A simple hash function from Robert Sedgwicks Algorithms in C book.</remarks>
    public sealed class Rs : HashAlgorithm
    {
        #region Fields

        private const uint _ASeed = 63689u;
        private const uint _b = 378551u;
        private const uint _DefaultSeed = 0;
        private uint _a;
        private uint _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Rs"/> class.
        /// </summary>
        public Rs()
        {
            HashSizeValue = 32;
            Initialize();
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Rs"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="Rs"/> class.</returns>
        public static new Rs Create()
        {
            return Create(typeof(Rs).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Rs"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="Rs"/> class.</returns>
        public static new Rs Create(string hashName)
        {
            return (Rs)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Sets the initial values of a <see cref="Rs"/> class.
        /// </summary>
        public override void Initialize()
        {
            _a = _ASeed;
            _hash = _DefaultSeed;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                unchecked
                {
                    _hash = _hash * _a + array[i];
                    _a = _a * _b;
                }
            }
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(_hash);
        }

        #endregion Methods
    }
}
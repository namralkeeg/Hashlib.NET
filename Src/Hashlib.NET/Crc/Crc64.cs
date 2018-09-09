using System;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.Crc
{
    /// <summary>
    /// A CRC-64 implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>
    /// Compute CRC-64 in the manner of xz, using the ECMA-182 polynomial, bit-reversed, with one's
    /// complement pre and post processing.
    /// https://en.wikipedia.org/wiki/Cyclic_redundancy_check
    /// </remarks>
    public sealed class Crc64 : HashAlgorithm
    {
        #region Fields

        #region Constants

        private const int _BitSize = sizeof(ulong) * 8;
        private const ulong _DefaultSeed = 0x0ul;

        // ECMA-182 Polynomial
        private const ulong _ECMA182Polynomial = 0xC96C5795D7870F42ul;

        // Iso 3309 Polynomial
        private const ulong _ISOPolynomial = 0xD800000000000000ul;

#if POLYISO
        // Use the ISO 3309 Polynomial by default only if specified at compile time.
        private const ulong _DefaultPolynomial = _ISOPolynomial;
#else
        // Use the ECMA-182 Polynomial by default.
        private const ulong _DefaultPolynomial = _ECMA182Polynomial;
#endif

        #endregion Constants

        private static ulong[] _defaultTable;
        private ulong _hash;
        private ulong _polynomial;
        private ulong _seed;
        private ulong[] _table;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a <see cref="Crc64"/> class.
        /// </summary>
        /// <param name="polynomial">They Polynomial to use for the crc calculation.</param>
        public Crc64(ulong polynomial) : this(_DefaultSeed, polynomial)
        { }

        /// <summary>
        /// Initializes a <see cref="Crc64"/> class.
        /// </summary>
        /// <param name="seed">The value to seed the crc calculation with.</param>
        /// <param name="polynomial">They Polynomial to use for the crc calculation.</param>
        public Crc64(ulong seed, ulong polynomial)
        {
            _seed = seed;
            _polynomial = polynomial;
            HashSizeValue = _BitSize;
            _table = InitializeTable(_polynomial);
            Initialize();
        }

        /// <summary>
        /// Initializes a <see cref="Crc64"/> class.
        /// </summary>
        public Crc64() : this(_DefaultSeed, _DefaultPolynomial)
        { }

        #endregion Constructors

        /// <summary>
        /// Gets and sets the polynomial to use in the CRC calculation.
        /// </summary>
        /// <remarks>Re-calculates the lookup table on change.</remarks>
        public ulong Polynomial
        {
            get => _polynomial;
            set
            {
                if (value != _polynomial)
                {
                    _polynomial = value;
                    _table = InitializeTable(_polynomial);
                    Initialize();
                }
            }
        }

        /// <summary>
        /// Gets and sets a value to seed the CRC calculaton with.
        /// </summary>
        public ulong Seed
        {
            get => _seed;
            set
            {
                _seed = value;
                Initialize();
            }
        }

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Crc64"/> class.
        /// </summary>
        /// <returns>A new instance of an <see cref="Crc64"/> class.</returns>
        public static new Crc64 Create()
        {
            return Create(typeof(Crc64).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Crc64"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of an <see cref="Crc64"/> class.</returns>
        public static new Crc64 Create(string hashName)
        {
            return (Crc64)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Initializes an instance of <see cref="Crc64"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _seed;
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ulong crc = ~_hash; // same as _hash ^ 0xFFFFFFFF
            for (int i = ibStart; i < ibStart + cbSize; i++)
            {
                crc = unchecked((crc >> 8) ^ _table[array[i] ^ (crc & 0xFF)]);
            }

            _hash = ~crc;  // same as crc ^ 0xFFFFFFFF
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>The computed hash as a byte array.</returns>
        protected override byte[] HashFinal() => BitConverter.GetBytes(_hash);

        private ulong[] InitializeTable(ulong polynomial)
        {
            // Use the default table if it's the default polynomial and the default table isn't empty.
            if ((polynomial == _DefaultPolynomial) && (_defaultTable != null))
                return _defaultTable;

            var createTable = new ulong[256];
            ulong entry;
            for (ulong i = 0; i < 256; i++)
            {
                entry = i;
                for (ulong j = 0; j < 8; ++j)
                {
                    if ((entry & 1) == 1)
                    {
                        entry = (entry >> 1) ^ polynomial;
                    }
                    else
                    {
                        entry >>= 1;
                    }
                }
                createTable[i] = entry;
            }

            // If it's the default polynomial, assign the new table to the default table.
            if (polynomial == _DefaultPolynomial)
                _defaultTable = createTable;

            return createTable;
        }

        #endregion Methods
    }
}
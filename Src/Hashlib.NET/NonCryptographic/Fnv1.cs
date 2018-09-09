using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using Hashlib.NET.Common;

namespace Hashlib.NET.NonCryptographic
{
    /// <summary>
    /// An FNV-1 implementation of the <see cref="HashAlgorithm"/> class.
    /// </summary>
    /// <remarks>See a detailed description at http://www.isthe.com/chongo/tech/comp/fnv/ </remarks>
    public class Fnv1 : HashAlgorithm
    {
        #region Fields

        protected const int _DefaultBitSize = 32;

        protected static readonly BigInteger _fnvMod1024;
        protected static readonly BigInteger _fnvMod128;
        protected static readonly BigInteger _fnvMod256;
        protected static readonly BigInteger _fnvMod32;
        protected static readonly BigInteger _fnvMod512;
        protected static readonly BigInteger _fnvMod64;
        protected static readonly BigInteger _fnvOffset1024;
        protected static readonly BigInteger _fnvOffset128;
        protected static readonly BigInteger _fnvOffset256;
        protected static readonly BigInteger _fnvOffset32;
        protected static readonly BigInteger _fnvOffset512;
        protected static readonly BigInteger _fnvOffset64;
        protected static readonly BigInteger _fnvPrime1024;
        protected static readonly BigInteger _fnvPrime128;
        protected static readonly BigInteger _fnvPrime256;
        protected static readonly BigInteger _fnvPrime32;
        protected static readonly BigInteger _fnvPrime512;
        protected static readonly BigInteger _fnvPrime64;
        protected int _bitSize;
        protected BigInteger _fnvMask;
        protected BigInteger _fnvMod;
        protected BigInteger _fnvOffset;
        protected BigInteger _fnvPrime;
        protected BigInteger _hash;

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes all the static variables in the <see cref="Fnv1"/> class.
        /// </summary>
        static Fnv1()
        {
            _fnvPrime32 = BigInteger.Parse("16777619");
            _fnvPrime64 = BigInteger.Parse("1099511628211");
            _fnvPrime128 = BigInteger.Parse("309485009821345068724781371");
            _fnvPrime256 = BigInteger.Parse("374144419156711147060143317175368453031918731002211");
            _fnvPrime512 = BigInteger.Parse("35835915874844867368919076489095108449946327955754392558399825615420669938882575" +
                "126094039892345713852759");
            _fnvPrime1024 = BigInteger.Parse("50164565101131186554345988110352789550307653454047907443030175238311120551081474" +
                "51509157692220295382716162651878526895249385292291816524375083746691371804094271" +
                "873160484737966720260389217684476157468082573");

            _fnvOffset32 = 2166136261u;
            _fnvOffset64 = 14695981039346656037ul;
            _fnvOffset128 = BigInteger.Parse("144066263297769815596495629667062367629");
            _fnvOffset256 = BigInteger.Parse("100029257958052580907070968620625704837092796014241193945225284501741471925557");
            _fnvOffset512 = BigInteger.Parse("96593031294966694980094354007163104660904187456726378961083743294344626579945829" +
                "32197716438449813051892206539805784495328239340083876191928701583869517785");
            _fnvOffset1024 = BigInteger.Parse("14197795064947621068722070641403218320880622795441933960878474914617582723252296" +
                "73230371772215086409652120235554936562817466910857181476047101507614802975596980" +
                "40773201576924585630032153049571501574036444603635505054127112859663616102678680" +
                "82893823963790439336411086884584107735010676915");

            _fnvMod32 = BigInteger.Pow(2, 32);
            _fnvMod64 = BigInteger.Pow(2, 64);
            _fnvMod128 = BigInteger.Pow(2, 128);
            _fnvMod256 = BigInteger.Pow(2, 256);
            _fnvMod512 = BigInteger.Pow(2, 512);
            _fnvMod1024 = BigInteger.Pow(2, 1024);
        }

        /// <summary>
        /// Initializes a <see cref="Fnv1"/> class.
        /// </summary>
        public Fnv1() : this(_DefaultBitSize)
        { }

        /// <summary>
        /// Initializes a <see cref="Fnv1"/> class.
        /// </summary>
        /// <param name="bitSize">The bit size of the FNV-1 hash to generate.</param>
        public Fnv1(int bitSize)
        {
            BitSize = bitSize;
            Initialize();
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Gets and sets the bit size to use for hash generation.
        /// </summary>
        /// <remarks>Needs to be between 8 and 1024 bits.</remarks>
        public int BitSize
        {
            get => _bitSize;
            set => SetBitSize(value);
        }

        /// <summary>
        /// The number of bits in the returned hash.
        /// </summary>
        public override int HashSize => _bitSize;

        #endregion Properties

        #region Methods

        /// <summary>
        /// Creates a new instance of a <see cref="Fnv1"/> class.
        /// </summary>
        /// <returns>A new instance of an <see cref="Fnv1"/> class.</returns>
        public static new Fnv1 Create()
        {
            return Create(typeof(Fnv1).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="Fnv1"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of an <see cref="Fnv1"/> class.</returns>
        public static new Fnv1 Create(string hashName)
        {
            return (Fnv1)HashAlgorithmFactory.Create(hashName);
        }

        /// <summary>
        /// Initializes an instance of <see cref="Fnv1"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hash = _fnvOffset;
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
                    _hash = ((_hash * _fnvPrime) ^ array[i]) % _fnvMod;
                }
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>The computed hash as a byte array.</returns>
        protected override byte[] HashFinal()
        {
            // If the hash isn't a power of two, compute the FNV hash that is just larger than x-bits
            // and xor-fold the result down to x-bits. By xor-folding we mean shift the excess high
            // order bits down and xor them with the lower x-bits.
            if (!IsPowerOfTwo(_bitSize))
            {
                var mask = BigInteger.Parse(new string('F', (_bitSize / 4) + (_bitSize % 4 != 0 ? 1 : 0)), 
                    NumberStyles.AllowHexSpecifier);
                _hash = (_hash >> _bitSize) ^ (mask & _hash);
            }

            return _hash.ToByteArray();
        }

        /// <summary>
        /// Determines if a number is a power of two.
        /// </summary>
        /// <param name="number">The number to check.</param>
        /// <returns>True if it is a power of two, false otherwise.</returns>
        protected bool IsPowerOfTwo(int number)
        {
            return (number != 0) && ((number & (number - 1)) == 0);
        }

        protected void SetBitSize(int bitSize)
        {
            if (bitSize < 8 || bitSize > 1024)
            {
                throw new ArgumentOutOfRangeException(nameof(bitSize), "Bit size is out of range.");
            }

            _bitSize = bitSize;

            if (_bitSize <= 32)
            {
                _fnvOffset = _fnvOffset32;
                _fnvPrime = _fnvPrime32;
                _fnvMod = _fnvMod32;
            }
            else if (_bitSize <= 64)
            {
                _fnvOffset = _fnvOffset64;
                _fnvPrime = _fnvPrime64;
                _fnvMod = _fnvMod64;
            }
            else if (_bitSize <= 128)
            {
                _fnvOffset = _fnvOffset128;
                _fnvPrime = _fnvPrime128;
                _fnvMod = _fnvMod128;
            }
            else if (_bitSize <= 256)
            {
                _fnvOffset = _fnvOffset256;
                _fnvPrime = _fnvPrime256;
                _fnvMod = _fnvMod256;
            }
            else if (_bitSize <= 512)
            {
                _fnvOffset = _fnvOffset512;
                _fnvPrime = _fnvPrime512;
                _fnvMod = _fnvMod512;
            }
            else // if (_bitSize <= 1024)
            {
                _fnvOffset = _fnvOffset1024;
                _fnvPrime = _fnvPrime1024;
                _fnvMod = _fnvMod1024;
            }

            Initialize();
        }

        #endregion Methods
    }
}
using System.Globalization;
using System.Numerics;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class Fnv1Tests
    {
        public class MultipleBytesArray32bit
        {
            private readonly Fnv1 _hashAlgorithm;

            public MultipleBytesArray32bit()
            {
                _hashAlgorithm = Fnv1.Create();
            }

            [Theory]
            [InlineData("0b4b1178b", "foob")]
            [InlineData("0fdc80fb0", "fooba")]
            [InlineData("031f0b262", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 32;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray64bit
        {
            private readonly Fnv1 _hashAlgorithm;

            public MultipleBytesArray64bit()
            {
                _hashAlgorithm = Fnv1.Create();
            }

            [Theory]
            [InlineData("0378817ee2ed65cb", "foob")]
            [InlineData("0d329d59b9963f790", "fooba")]
            [InlineData("0340d8765a4dda9c2", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 64;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray128bit
        {
            private readonly Fnv1 _hashAlgorithm;

            public MultipleBytesArray128bit()
            {
                _hashAlgorithm = Fnv1.Create();
            }

            [Theory]
            [InlineData("066AB68F6C1757277B806E89C7057C4AB", "foob")]
            [InlineData("0F15A7F64B683D94F7080387E3BFEFE08", "fooba")]
            [InlineData("07896BFEA9C3C64BF6DC58353D2C293AA", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 128;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }
    }
}
using System.Text;
using Hashlib.NET.NonCryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class MurmurHash128x64Tests
    {
        public class MultipleBytesArray
        {
            private readonly MurmurHash128 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new MurmurHash3x64_128();
            }

            [Theory]
            [InlineData("F8EA585D207F74D2FABE264B60DBBDFA", "foob")]
            [InlineData("19F951BFDD2F21F26642DDA789509842", "fooba")]
            [InlineData("455AC81671AED2BDAFD6F8BAE055A274", "foobar")]
            public void ComputeHash_WithMultipleBytes(string expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArrayWithSeed
        {
            private readonly MurmurHash128 _hashAlgorithm;

            public MultipleBytesArrayWithSeed()
            {
                _hashAlgorithm = new MurmurHash3x64_128();
            }

            [Theory]
            [InlineData("1AC6A9DFCE34CEF1CE34CEF1CE34CEF1", "foob", 1u)]
            [InlineData("6A0AF35EE4ADD5FC3182D7013182D701", "fooba", 1u)]
            [InlineData("3DBE0F181FB13216964F1E1C964F1E1C", "foobar", 1u)]
            public void ComputeHash_WithMultipleBytes(string expected, string testString, uint seed)
            {
                _hashAlgorithm.Seed = seed;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result);
                Assert.Equal(expected, hash);
            }
        }
    }
}

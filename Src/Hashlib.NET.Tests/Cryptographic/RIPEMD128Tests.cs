using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class RIPEMD128Tests
    {
        public class OfficialTestVectors
        {
            private readonly RIPEMD128 _hashAlgorithm;

            public OfficialTestVectors()
            {
                _hashAlgorithm = new RIPEMD128();
            }

            [Theory]
            [InlineData("86be7afa339d0fc7cfc785e72f578d33", "a")]
            [InlineData("c14a12199c66e4ba84636b0f69144c77", "abc")]
            [InlineData("9e327b3d6e523062afc1132d7df9d1b8", "message digest")]
            [InlineData("fd2aa607f71dc8f510714922b371834e", "abcdefghijklmnopqrstuvwxyz")]
            [InlineData("a1aa0689d0fafa2ddc22e88b49133a06",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")]
            [InlineData("d1e959eb179c911faea4624c60c5c702",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")]
            [InlineData("3f45ef194732c2dbb2c4a2c769795fa3",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890")]
            public void ComputHash_WithOfficialTestVectors(string expected, string testString)
            {
                _hashAlgorithm.InParallel = true;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArray
        {
            private readonly RIPEMD128 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new RIPEMD128();
            }

            [Theory]
            [InlineData("302ACF33344CDDE8C59F3E3D3D43A6F3", "foob")]
            [InlineData("92480C1107E6AD7D5C134AD3420AD1D7", "fooba")]
            [InlineData("DE1AFAA7EF7D81A4B10B84EBCAAB241B", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.InParallel = true;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result);
                Assert.Equal(expected, hash);
            }
        }
    }
}

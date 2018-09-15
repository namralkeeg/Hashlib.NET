using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class RIPEMD160Tests
    {
        public class OfficialTestVectors
        {
            private readonly RIPEMD160 _hashAlgorithm;

            public OfficialTestVectors()
            {
                _hashAlgorithm = new RIPEMD160();
            }

            [Theory]
            [InlineData("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a")]
            [InlineData("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc")]
            [InlineData("5d0689ef49d2fae572b881b123a85ffa21595f36", "message digest")]
            [InlineData("f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "abcdefghijklmnopqrstuvwxyz")]
            [InlineData("12a053384a9c0c88e405a06c27dcf49ada62eb2b", 
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")]
            [InlineData("b0e20b6e3116640286ed3a87a5713079b21f5189", 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")]
            [InlineData("9b752e45573d4b39f4dbd3323cab82bf63326bfb", 
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
            private readonly RIPEMD160 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new RIPEMD160();
            }

            [Theory]
            [InlineData("AF992AC91D0CB3D7FC9949E2DF9CC0FB06FD1C6C", "foob")]
            [InlineData("B2F5AD02FCCBD3B9DF821426066114B1965084E1", "fooba")]
            [InlineData("A06E327EA7388C18E4740E350ED4E60F2E04FC41", "foobar")]
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

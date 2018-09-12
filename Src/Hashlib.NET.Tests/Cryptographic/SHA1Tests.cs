using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class SHA1Tests
    {
        public class MultipleBytesArray
        {
            private readonly SHA1 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = SHA1.Create();
            }

            [Theory]
            [InlineData("2CA60EC33DA4CCDF3C5B4944A2E831A70D76D7C7", "foob")]
            [InlineData("BF3F6E65DAA76DDE92612355478885EB52473854", "fooba")]
            [InlineData("8843D7F92416211DE9EBB963FF4CE28125932878", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result);
                Assert.Equal(expected, hash);
            }
        }
    }
}
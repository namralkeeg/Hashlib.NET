using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class RsTests
    {
        public class MultipleBytesArray
        {
            private readonly Rs _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Rs.Create();
            }

            [Theory]
            [InlineData(0x809347F2u, "foob")]
            [InlineData(0xBE6F3AA3u, "fooba")]
            [InlineData(0xB50ABEFFu, "foobar")]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}
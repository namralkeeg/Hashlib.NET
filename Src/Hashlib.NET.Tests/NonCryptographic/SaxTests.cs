using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class SaxTests
    {
        public class MultipleBytesArray
        {
            private readonly Sax _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Sax.Create();
            }

            [Theory]
            [InlineData(0x003557a3u, "foob")]
            [InlineData(0x068d1d0au, "fooba")]
            [InlineData(0xd5cbf5feu, "foobar")]
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
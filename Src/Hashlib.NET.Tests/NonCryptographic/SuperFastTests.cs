using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class SuperFastTests
    {
        public class MultipleBytesArray
        {
            private readonly SuperFast _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = SuperFast.Create();
            }

            [Theory]
            [InlineData(0x58C9CBD5u, "foob")]
            [InlineData(0xF9D871C8u, "fooba")]
            [InlineData(0xA6BCDCA9u, "foobar")]
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

using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class XxHash32Tests
    {
        public class MultipleBytesArray
        {
            private readonly XxHash32 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = XxHash32.Create();
            }

            [Theory]
            [InlineData(0x5d81fdb0u, "foob")]
            [InlineData(0x940e43aau, "fooba")]
            [InlineData(0xeda34aafu, "foobar")]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData(0x8208a79bu, "foob")]
            [InlineData(0x1f87f8f6u, "fooba")]
            [InlineData(0xc047b030u, "foobar")]
            public void ComputeHash_WithMultipleBytesWithSeed(uint expected, string testString)
            {
                _hashAlgorithm.Seed = 42;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}

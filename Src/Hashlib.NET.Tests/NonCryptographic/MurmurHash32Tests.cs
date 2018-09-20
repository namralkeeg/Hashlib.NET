using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class MurmurHash32Tests
    {
        public class MultipleBytesArray
        {
            private readonly MurmurHash32 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = MurmurHash32.Create();
            }

            [Theory]
            [InlineData(0xE79C6447u, "foob")]
            [InlineData(0xB61A8D12u, "fooba")]
            [InlineData(0xA4C4D4BDu, "foobar")]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArrayWithSeed
        {
            private readonly MurmurHash32 _hashAlgorithm;

            public MultipleBytesArrayWithSeed()
            {
                _hashAlgorithm = MurmurHash32.Create();
            }

            [Theory]
            [InlineData(0x8F639DF1u, "foob", 1u)]
            [InlineData(0xC3901D81u, "fooba", 1u)]
            [InlineData(0x6C9B7A46u, "foobar", 1u)]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString, uint seed)
            {
                _hashAlgorithm.Seed = seed;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}
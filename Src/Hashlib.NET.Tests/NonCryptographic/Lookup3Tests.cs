using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class Lookup3Tests
    {
        public class MultipleBytesArray
        {
            private readonly Lookup3 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new Lookup3();
            }

            [Theory]
            [InlineData(0x2910B052u, "foob")]
            [InlineData(0xC1895E0Eu, "fooba")]
            [InlineData(0x17770551u, "Four score and seven years ago")]
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
            private readonly Lookup3 _hashAlgorithm;

            public MultipleBytesArrayWithSeed()
            {
                _hashAlgorithm = new Lookup3();
            }

            [Theory]
            [InlineData(0xA3FF0B2Bu, "foob", 1u)]
            [InlineData(0xBCC5C559u, "fooba", 1u)]
            [InlineData(0xCD628161u, "Four score and seven years ago", 1u)]
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

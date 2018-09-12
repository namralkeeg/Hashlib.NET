using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class XxHash64Tests
    {
        public class MultipleBytesArray
        {
            private readonly XxHash64 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = XxHash64.Create();
            }

            [Theory]
            [InlineData(0x27b271e5d617029eul, "foob")]
            [InlineData(0x928dbefa262670daul, "fooba")]
            [InlineData(0xa2aa05ed9085aaf9ul, "foobar")]
            public void ComputeHash_WithMultipleBytes(ulong expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt64(result, 0);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData(0x16d00d29d008d40cul, "foob")]
            [InlineData(0xf0a621d2c24b5bf4ul, "fooba")]
            [InlineData(0x7ed2a7f3d2a41099ul, "foobar")]
            public void ComputeHash_WithMultipleBytesWithSeed(ulong expected, string testString)
            {
                _hashAlgorithm.Seed = 42;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt64(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}

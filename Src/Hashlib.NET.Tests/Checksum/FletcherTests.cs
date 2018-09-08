using System;
using System.Text;
using Hashlib.NET.Checksum;
using Xunit;

namespace Hashlib.NET.Tests.Checksum
{
    public class FletcherTests
    {
        public class MultipleBytesArray16
        {
            private readonly Fletcher16 _hashAlgorithm;

            public MultipleBytesArray16()
            {
                _hashAlgorithm = Fletcher16.Create();
            }

            [Theory]
            [InlineData(51440u, "abcde")]
            [InlineData(8279u, "abcdef")]
            [InlineData(1575u, "abcdefgh")]
            public void ComputHash_WithMultipleBytes(uint expected, string testString)
            {
                _hashAlgorithm.Initialize();
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt16(result, 0);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArray32
        {
            private readonly Fletcher32 _hashAlgorithm;

            public MultipleBytesArray32()
            {
                _hashAlgorithm = Fletcher32.Create();
            }

            [Theory]
            [InlineData(4031760169u, "abcde")]
            [InlineData(1448095018u, "abcdef")]
            [InlineData(3957429649u, "abcdefgh")]
            public void ComputHash_WithMultipleBytes(uint expected, string testString)
            {
                _hashAlgorithm.Initialize();
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}
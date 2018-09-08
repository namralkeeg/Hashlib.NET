using System;
using System.Text;
using Hashlib.NET.Crc;
using Xunit;

namespace Hashlib.NET.Tests.Crc
{
    public class Crc32Tests
    {
        public class MultipleBytesArray
        {
            private readonly Crc32 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Crc32.Create();
            }

            [Theory]
            [InlineData(0x8587D865u, "abcde")]
            [InlineData(0x4B8E39EFu, "abcdef")]
            [InlineData(0xAEEF2A50u, "abcdefgh")]
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
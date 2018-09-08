using System;
using System.Text;
using Hashlib.NET.Crc;
using Xunit;

namespace Hashlib.NET.Tests.Crc
{
    public class Crc64Tests
    {
        public class MultipleBytesArray
        {
            private readonly Crc64 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Crc64.Create();
            }

            [Theory]
            [InlineData(0x995dc9bbdf1939faul, "123456789")]
            [InlineData(0x27db187fc15bbc72ul, "This is a test of the emergency broadcast system.")]
            public void ComputHash_WithMultipleBytes(ulong expected, string testString)
            {
                _hashAlgorithm.Initialize();
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt64(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}
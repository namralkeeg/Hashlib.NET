using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class Elf32Tests
    {
        public class MultipleBytesArray
        {
            private readonly Elf32 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Elf32.Create();
            }

            [Theory]
            [InlineData(0x0006d652u, "foob")]
            [InlineData(0x006d6581u, "fooba")]
            [InlineData(0x06d65882u, "foobar")]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString)
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
using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class DekTests
    {
        public class MultipleBytesArray
        {
            private readonly Dek _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Dek.Create();
            }

            [Theory]
            [InlineData(0x72B182u, "foob")]
            [InlineData(0xC563021u, "fooba")]
            [InlineData(0x4AC60453u, "foobar")]
            public void ComputHash_WithMultipleBytes(uint expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}
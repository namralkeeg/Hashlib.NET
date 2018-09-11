using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class SdbmTests
    {
        public class MultipleBytesArray
        {
            private readonly Sdbm _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Sdbm.Create();
            }

            [Theory]
            [InlineData(0xc0cf00bcu, "foob")]
            [InlineData(0x73ad2ea5u, "fooba")]
            [InlineData(0xa6437b0du, "foobar")]
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
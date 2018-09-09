using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class ApTests
    {
        public class MultipleBytesArray
        {
            private readonly Ap _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Ap.Create();
            }

            [Theory]
            [InlineData(0xcef69bd9u, "foob")]
            [InlineData(0xac65a443u, "fooba")]
            [InlineData(0x7bdb6eecu, "foobar")]
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
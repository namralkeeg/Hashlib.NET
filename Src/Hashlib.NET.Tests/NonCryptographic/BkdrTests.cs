using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class BkdrTests
    {
        public class MultipleBytesArray
        {
            private readonly Bkdr _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Bkdr.Create();
            }

            [Theory]
            [InlineData(0x0dc835d8u, "foob")]
            [InlineData(0x0d738de9u, "fooba")]
            [InlineData(0xe2219eadu, "foobar")]
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
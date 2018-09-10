using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class JoaatTests
    {
        public class MultipleBytesArray
        {
            private readonly Joaat _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Joaat.Create();
            }

            [Theory]
            [InlineData(0x2e302f0du, "foob")]
            [InlineData(0x62b4474bu, "fooba")]
            [InlineData(0xf952fde7u, "foobar")]
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
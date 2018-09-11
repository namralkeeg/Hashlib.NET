using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class JsTests
    {
        public class MultipleBytesArray
        {
            private readonly Js _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Js.Create();
            }

            [Theory]
            [InlineData(0x409c7f1cu, "foob")]
            [InlineData(0x632b7cb4u, "fooba")]
            [InlineData(0x1d110aabu, "foobar")]
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
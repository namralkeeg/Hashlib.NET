using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class Djb2Tests
    {
        public class MultipleBytesArray
        {
            private readonly Djb2 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Djb2.Create();
            }

            [Theory]
            [InlineData(0x7c96e50bu, "foob")]
            [InlineData(0x0f7386ccu, "fooba")]
            [InlineData(0xfde460beu, "foobar")]
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
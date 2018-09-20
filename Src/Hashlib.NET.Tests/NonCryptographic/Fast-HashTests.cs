using System;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class Fast_HashTests
    {
        public class MultipleBytesArray32Bit
        {
            private readonly Fast_Hash _hashAlgorithm;

            public MultipleBytesArray32Bit()
            {
                _hashAlgorithm = new Fast_Hash();
            }

            [Theory]
            [InlineData(0x0BFAAC51u, "foob")]
            [InlineData(0x5712F2BBu, "fooba")]
            [InlineData(0x2E88F6A3u, "foobar")]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArrayWithSeed32Bit
        {
            private readonly Fast_Hash _hashAlgorithm;

            public MultipleBytesArrayWithSeed32Bit()
            {
                _hashAlgorithm = new Fast_Hash();
            }

            [Theory]
            [InlineData(0x121A93C4u, "foob", 1u)]
            [InlineData(0x17C31538u, "fooba", 1u)]
            [InlineData(0x8E0D7D75u, "foobar", 1u)]
            public void ComputeHash_WithMultipleBytes(uint expected, string testString, uint seed)
            {
                _hashAlgorithm.Seed = seed;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArray64Bit
        {
            private readonly Fast_Hash _hashAlgorithm;

            public MultipleBytesArray64Bit()
            {
                _hashAlgorithm = new Fast_Hash();
            }

            [Theory]
            [InlineData(0xEF6FDF4AFB6A8B9Bul, "foob")]
            [InlineData(0x7CC84E91D3DB414Cul, "fooba")]
            [InlineData(0xA8B312E5D73C0988ul, "foobar")]
            public void ComputeHash_WithMultipleBytes(ulong expected, string testString)
            {
                _hashAlgorithm.BitSize = NET.Common.BitSize.Bits64;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt64(result, 0);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArrayWithSeed64Bit
        {
            private readonly Fast_Hash _hashAlgorithm;

            public MultipleBytesArrayWithSeed64Bit()
            {
                _hashAlgorithm = new Fast_Hash();
            }

            [Theory]
            [InlineData(0x000000001FC708FCul, "foob", 1ul)]
            [InlineData(0x00000000B973A46Dul, "fooba", 1ul)]
            [InlineData(0x0000000022295D01ul, "foobar", 1ul)]
            public void ComputeHash_WithMultipleBytes(ulong expected, string testString, ulong seed)
            {
                _hashAlgorithm.BitSize = NET.Common.BitSize.Bits64;
                _hashAlgorithm.Seed = seed;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = BitConverter.ToUInt32(result, 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}

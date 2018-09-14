using System;
using System.Text;
using Hashlib.NET.Common;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class KeccakTests
    {
        public class CheckBitSize
        {
            private readonly Keccak _hashAlgorithm;

            public CheckBitSize()
            {
                _hashAlgorithm = Keccak.Create();
            }

            [Fact]
            public void BitSize_WithInvalidBitSize_ShouldThrowAgumentOutOfRangeException()
            {
                var ex = Record.Exception(() => _hashAlgorithm.BitSize = BitSize.Bits32);
                Assert.NotNull(ex);
                Assert.IsType<ArgumentOutOfRangeException>(ex);
            }
        }

        public class MultipleBytesArray
        {
            private readonly Keccak _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = Keccak.Create();
            }

            [Theory]
            [InlineData("4241274c69659644d9c9f3642c1f760585fc118fd61af4f0bfbe0b53", "foob")]
            [InlineData("a9dae670392091bd560f0f462eeb4a8bb04f241e6383f424ae69c88c", "fooba")]
            [InlineData("f5dd6617f67e2b6a7b5ef75d1931ef36ee63ca35d06bcc714a74a386", "foobar")]
            public void ComputHash_WithMultipleBytes224(string expected, string testString)
            {
                _hashAlgorithm.BitSize = BitSize.Bits224;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData("40ae26f6f78f964402dde307e9408de7eeebd5d57c2308c31640115104f50596", "foob")]
            [InlineData("7bc3de87066e51a097b88e8833bad69d8b22a6ff08e577373e9173a262b209b7", "fooba")]
            [InlineData("38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e", "foobar")]
            public void ComputHash_WithMultipleBytes256(string expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData("869bea5d3fb17d8ec010d7b44ff985741db2f211d0ddeee61d0dbd364d83438c" +
                "cdaf46df0c091048dc43cf4a9c8ec974", "foob")]
            [InlineData("ae2fa1af2cd8732ba064e4f0194f2dc080b2f81a2ce81e54d408a61035d58397" +
                "282d181a93cc795764f72ddbc57be89a", "fooba")]
            [InlineData("e8c02310ada7fbf1c550713cdaa0a3eaf02ee13990f73851e7e5a183f99df541" +
                "d833424e702e4e22eb4306b7bcbeb965", "foobar")]
            public void ComputHash_WithMultipleBytes384(string expected, string testString)
            {
                _hashAlgorithm.BitSize = BitSize.Bits384;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData("2e79d93a1179298e2d752c141b5664a21b7dd145023f4cdfbcaca6b73efaa7ba" +
                "2fd694b56c9c330797344f0ded483997fe54c89091caaa4a00eacee276d5054e", "foob")]
            [InlineData("c8b77f61d874d7b88e4d8c94fe1231be24c044a6545db626692b494f07ec06ea" +
                "5f982cdf8f75fcf34275eddc4d9f246efe5ac9c5239835fe363ded7aabb14f7b", "fooba")]
            [InlineData("927618d193a11374f6072cdcb8c410e2f18e0c433eb35a9f11ce3035b0066811" +
                "db6c03a723a2855c4a8ee2b1c842e28d4982a1ff312dd4ddaf807b96d4d2ee1b", "foobar")]
            public void ComputHash_WithMultipleBytes512(string expected, string testString)
            {
                _hashAlgorithm.BitSize = BitSize.Bits512;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }
        }
    }
}
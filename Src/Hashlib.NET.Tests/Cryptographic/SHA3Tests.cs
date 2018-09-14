using System;
using System.Text;
using Hashlib.NET.Common;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class SHA3Tests
    {
        public class CheckBitSize
        {
            private readonly SHA3 _hashAlgorithm;

            public CheckBitSize()
            {
                _hashAlgorithm = SHA3.Create();
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
            private readonly SHA3 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = SHA3.Create();
            }

            [Theory]
            [InlineData("a3f74cb1a755b9cb6bd71e82d92284b80f5ffa1246e2235b9826e765", "foob")]
            [InlineData("0e4932c1b5322828364d814fe30c1e83b9791979397d3fefff19018f", "fooba")]
            [InlineData("1ad852ba147a715fe5a3df39a741fad08186c303c7d21cefb7be763b", "foobar")]
            public void ComputHash_WithMultipleBytes224(string expected, string testString)
            {
                _hashAlgorithm.BitSize = BitSize.Bits224;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData("88d7064be34ed3873614ce9359ef4a84f0ac78103f7f9f70c13d2b2e8f525c25", "foob")]
            [InlineData("5a9ae8ba629082f6c0b367c5dc95385a592adbde14101fab622313e5f8bc0f08", "fooba")]
            [InlineData("09234807e4af85f17c66b48ee3bca89dffd1f1233659f9f940a2b17b0b8c6bc5", "foobar")]
            public void ComputHash_WithMultipleBytes256(string expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData("7f68cb4a78c1db71aa25193d5ce7a7ca1b5d486dc1bb7e6945c9a2d367275d67" +
                "3ae851a7b6738a44b75a4905d8b2315f", "foob")]
            [InlineData("434df34b227202800b4f6a87a440c7c969055b28eb4a21fd5984d38bd5b3eced" +
                "3f753296545d9176b959a682c440ecc7", "fooba")]
            [InlineData("0fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f06" +
                "8580f9c6c66f699b496c2da1cbcc7ed8", "foobar")]
            public void ComputHash_WithMultipleBytes384(string expected, string testString)
            {
                _hashAlgorithm.BitSize = BitSize.Bits384;
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result, true);
                Assert.Equal(expected, hash);
            }

            [Theory]
            [InlineData("37c0083c9cc8aa2aa01c7a8a130dcf3d9d11735a2ebb14d7979a116a3b8a86f8" +
                "8dfa1621427f50253968caf09f271f79c4ff8d415e6fcd076ae073195adf8aef", "foob")]
            [InlineData("9fecfde9cbbc0deca50d06c1ddc2a7274ef18a4d1ea6cab91d854420c865cb92" +
                "c9b9c67b6378b6e495068c4a31b1fbe1fd0ab3ccab4202e098662989845132df", "fooba")]
            [InlineData("ff32a30c3af5012ea395827a3e99a13073c3a8d8410a708568ff7e6eb85968fc" +
                "cfebaea039bc21411e9d43fdb9a851b529b9960ffea8679199781b8f45ca85e2", "foobar")]
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

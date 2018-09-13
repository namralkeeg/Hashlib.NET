using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class SHA256Tests
    {
        public class MultipleBytesArray
        {
            private readonly SHA256 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = SHA256.Create();
            }

            [Theory]
            [InlineData("A7452118BFC838EE7B2AAC14A8BC88C50A1AE4620903C4F8CDD327BB79961899", "foob")]
            [InlineData("41CBE1A87981490351CCAD5346D96DA0AC10678670B31FC0AB209AED1B5BC515", "fooba")]
            [InlineData("C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result);
                Assert.Equal(expected, hash);
            }
        }
    }
}

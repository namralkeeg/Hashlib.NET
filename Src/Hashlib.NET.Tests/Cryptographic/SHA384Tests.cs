using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class SHA384Tests
    {
        public class MultipleBytesArray
        {
            private readonly SHA384 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new SHA384();
            }

            [Theory]
            [InlineData("F89F010E0812B0339A800D2C5E0D1855BA8C67DD2E46062EC98301DD86C9AFE4" +
                "1BFC8977A660668FD51AA477ECE25769", "foob")]
            [InlineData("606EC7945195B315EA67ABC2623CCEA6208A74F3050FAEA29159C3712C2B27CD" +
                "05D30DB5B304BD92E6161AB7BB1BC634", "fooba")]
            [InlineData("3C9C30D9F665E74D515C842960D4A451C83A0125FD3DE7392D7B37231AF10C72" +
                "EA58AEDFCDF89A5765BF902AF93ECF06", "foobar")]
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

using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class SHA224Tests
    {
        public class MultipleBytesArray
        {
            private readonly SHA224 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = SHA224.Create();
            }

            [Theory]
            [InlineData("c853c23805496c81732670071b3dc6572ada09d2d772257285287667", "foob")]
            [InlineData("4e6373f8a06104e0e96f0ef2fe34ba5c9ace2a05307ac55a196128c8", "fooba")]
            [InlineData("de76c3e567fca9d246f5f8d3b2e704a38c3c5e258988ab525f941db8", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = Utils.BytesToHex(result);
                Assert.Equal(expected.ToUpper(), hash);
            }
        }
    }
}

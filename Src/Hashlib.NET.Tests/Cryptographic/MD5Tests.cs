using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class MD5Tests
    {
        public class MultipleBytesArray
        {
            private readonly MD5 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = MD5.Create();
            }

            [Theory]
            [InlineData("D0871A2B53C62DE5E046FEDE42F3F7AB", "foob")]
            [InlineData("73CF88A0B4A18C88A3996FA3D5B69A46", "fooba")]
            [InlineData("3858F62230AC3C915F300C664312C63F", "foobar")]
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
using System.Text;
using Hashlib.NET.Cryptographic;
using Hashlib.NET.Tests.Common;
using Xunit;

namespace Hashlib.NET.Tests.Cryptographic
{
    public class SHA512Tests
    {
        public class MultipleBytesArray
        {
            private readonly SHA512 _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new SHA512();
            }

            [Theory]
            [InlineData("FE20833E578F094C7828D07A504E91507854BF748FAB151979214463D1732B6A" +
                "695D0D476A8AE962326295E3E5A49491220988E8587932B51310D9BFE007406C", "foob")]
            [InlineData("3DF1E55106A2C94958BD5BB3164C53F69741A82403E72963F07E79D672938490" +
                "14BFAEAA0C4564C00F4F65E8C68237BABFBA57736864ED59858D16DF4110E4A6", "fooba")]
            [InlineData("0A50261EBD1A390FED2BF326F2673C145582A6342D523204973D0219337F8161" +
                "6A8069B012587CF5635F6925F1B56C360230C19B273500EE013E030601BF2425", "foobar")]
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
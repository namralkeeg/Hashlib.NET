using System.Globalization;
using System.Numerics;
using System.Text;
using Hashlib.NET.NonCryptographic;
using Xunit;

namespace Hashlib.NET.Tests.NonCryptographic
{
    public class Fnv1aTests
    {
        public class MultipleBytesArray32bit
        {
            private readonly Fnv1a _hashAlgorithm;

            public MultipleBytesArray32bit()
            {
                _hashAlgorithm = Fnv1a.Create();
            }

            [Theory]
            [InlineData("03f5076ef", "foob")]
            [InlineData("039aaa18a", "fooba")]
            [InlineData("0bf9cf968", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 32;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray64bit
        {
            private readonly Fnv1a _hashAlgorithm;

            public MultipleBytesArray64bit()
            {
                _hashAlgorithm = Fnv1a.Create();
            }

            [Theory]
            [InlineData("0dd120e790c2512af", "foob")]
            [InlineData("0cac165afa2fef40a", "fooba")]
            [InlineData("085944171f73967e8", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 64;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray128bit
        {
            private readonly Fnv1a _hashAlgorithm;

            public MultipleBytesArray128bit()
            {
                _hashAlgorithm = Fnv1a.Create();
            }

            [Theory]
            [InlineData("0696A39196D757277B806E974E013B7EF", "foob")]
            [InlineData("02A9456013D83D94F708142CFB842DBBA", "fooba")]
            [InlineData("0343E1662793C64BF6F0D3597BA446F18", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 128;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray256bit
        {
            private readonly Fnv1a _hashAlgorithm;

            public MultipleBytesArray256bit()
            {
                _hashAlgorithm = Fnv1a.Create();
            }

            [Theory]
            [InlineData("0E46DDD4ED460B1F6D8DD2E459F2A8E9D123F79D831721584CC463C26C4B0184F", "foob")]
            [InlineData("0366F691CC852F0136ACF588BB803C3D04E05F6CC9133D727456569C2C03187CA", "fooba")]
            [InlineData("0B055EA2F306CADAD4F0F81C02D3889DC32453DAD5AE35B753BA1A91084AF3428", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 256;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray512bit
        {
            private readonly Fnv1a _hashAlgorithm;

            public MultipleBytesArray512bit()
            {
                _hashAlgorithm = Fnv1a.Create();
            }

            [Theory]
            [InlineData("0F9FE9EEFE38CA43FCF36C8FBC0D25BEF535A6C1F4C00000000002A5259A146C7" +
                "F24CAE042D99828E5BABA0A28B18BF530DE9C3137CA2A36973F8D11981038627", "foob")]
            [InlineData("096B20C29347DFB41B5E3EBF2C34D2679C7A7E1751A0000000038B4561715D5E5" +
                "A4BD279918ADECBCD2F439C85E285847A4345F1BFDE8F24A6260292BDBB8E7CA", "fooba")]
            [InlineData("0B0EC738D9C6FD969D05F0B35F6C0ED53ADCACCCD8E0000004BF99F58EE4196AF" +
                "B9700E20110830FEA5396B76280E47FD022B6E81331CA1A9CED729C364BE7788", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 512;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }

        public class MultipleBytesArray1024bit
        {
            private readonly Fnv1a _hashAlgorithm;

            public MultipleBytesArray1024bit()
            {
                _hashAlgorithm = Fnv1a.Create();
            }

            [Theory]
            [InlineData("026F791F9147AEDAD1354BEF7D238F3219005CBD6E8D664F6B4EEFDBE94929E41" +
                "548C07154C2DC000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000001BA08046E07E0418FB7BE0EC07B8EA87A61BB4F07" +
                "3E2BAB740DB8398EF60CB9B50BF8D0FE3C5EB", "foob")]
            [InlineData("3E27F563B2CA82D6F6B22A35117DDFB386BAB86B4E52A63E0AA457BA1B5D6C250" +
                "5291FCD055F4B600000000000000000000000000000000000000000000000000000000000" +
                "00000000000000000000000000000002AD7E6EDEA236C5ABDFF1BCE07F9C3B45C98F798E3" +
                "B69B8E2F946B142B391BBFDC390DC1A4395702", "fooba")]
            [InlineData("631175FA7AE643AD08723D312C9FD024ADB91F77F6B19587197A22BCDF2372716" +
                "6C4572D0B985D5AE000000000000000000000000000000000000000000000000000000000" +
                "00000000000000000000000000000004270D11EF418EF08B8A49E1E825E547EB39937F819" +
                "222F3B7FC92A0E4707900888847A554BACEC98B0", "foobar")]
            public void ComputHash_WithMultipleBytes(string expected, string testString)
            {
                _hashAlgorithm.Initialize();
                _hashAlgorithm.BitSize = 1024;
                var expectedInteger = BigInteger.Parse(expected, NumberStyles.AllowHexSpecifier);
                var bytes = Encoding.UTF8.GetBytes(testString);
                var result = _hashAlgorithm.ComputeHash(bytes, 0, bytes.Length);
                var hash = new BigInteger(result);
                Assert.Equal(expectedInteger, hash);
            }
        }
    }
}
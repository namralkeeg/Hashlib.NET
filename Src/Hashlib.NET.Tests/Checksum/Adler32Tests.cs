#region Copyright

/*
 * Copyright (C) 2018 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#endregion Copyright

using System;
using System.Security.Cryptography;
using System.Text;
using Hashlib.NET.Checksum;
using Xunit;

namespace Hashlib.NET.Tests.Checksum
{
    public class Adler32Tests
    {
        public class EmptyByteArray
        {
            private readonly HashAlgorithm _hashAlgorithm;

            public EmptyByteArray()
            {
                _hashAlgorithm = new Adler32();
            }

            [Fact]
            public void ComputeHash_WithEmptyByteArray_ShouldThrowArgumentNullException()
            {
                _hashAlgorithm.Initialize();
                var ex = Record.Exception(() => _hashAlgorithm.ComputeHash(null, 0, 0));
                Assert.NotNull(ex);
                Assert.IsType<ArgumentNullException>(ex);
            }
        }

        public class SingleByteArray
        {
            private readonly HashAlgorithm _hashAlgorithm;

            public SingleByteArray()
            {
                _hashAlgorithm = new Adler32();
            }

            [Theory]
            [InlineData(0x620062u, "a")]
            [InlineData(0x630063u, "b")]
            public void ComputHash_WithSingleByte(uint expected, string testString)
            {
                _hashAlgorithm.Initialize();
                var bytes = Encoding.UTF8.GetBytes(testString);
                var hash = BitConverter.ToUInt32(_hashAlgorithm.ComputeHash(bytes, 0, bytes.Length), 0);
                Assert.Equal(expected, hash);
            }
        }

        public class MultipleBytesArray
        {
            private readonly HashAlgorithm _hashAlgorithm;

            public MultipleBytesArray()
            {
                _hashAlgorithm = new Adler32();
            }

            [Theory]
            [InlineData(0x11E60398, "Wikipedia")]
            public void ComputHash_WithMultipleBytes(uint expected, string testString)
            {
                _hashAlgorithm.Initialize();
                var bytes = Encoding.UTF8.GetBytes(testString);
                var hash = BitConverter.ToUInt32(_hashAlgorithm.ComputeHash(bytes, 0, bytes.Length), 0);
                Assert.Equal(expected, hash);
            }
        }
    }
}
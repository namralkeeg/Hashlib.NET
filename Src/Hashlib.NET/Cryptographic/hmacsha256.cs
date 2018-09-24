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

using Hashlib.NET.Common;

namespace Hashlib.NET.Cryptographic
{
    /// <summary>
    /// A <see cref="SHA256"/> HMAC keyed hash implementation of the <see cref="HMAC{T}"/> class.
    /// </summary>
    /// <remarks>A concrete SHA2-256 HMAC class derived from <see cref="HMAC{T}"/>.</remarks>
    public class HMACSHA256 : HMAC<SHA256>
    {
        /// <summary>
        /// Creates a new instance of a <see cref="HMACSHA256"/> class.
        /// </summary>
        /// <returns>A new instance of a <see cref="HMACSHA256"/> class.</returns>
        public static new HMACSHA256 Create()
        {
            return Create(typeof(HMACSHA256).Name);
        }

        /// <summary>
        /// Creates a new instance of a <see cref="HMACSHA256"/> class.
        /// </summary>
        /// <param name="hashName">The name of the class to create.</param>
        /// <returns>A new instance of a <see cref="HMACSHA256"/> class.</returns>
        public static new HMACSHA256 Create(string hashName)
        {
            return (HMACSHA256)HashAlgorithmFactory.Create(hashName);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace Hashlib.NET.Common
{
    public interface ICryptographicBlockHash : ICryptographicHash
    {
        /// <summary>
        /// The size in bytes of each block that's processed at once.
        /// </summary>
        int BlockSize { get; }
    }
}

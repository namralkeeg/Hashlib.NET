using System;
using System.IO;
using System.Security.Cryptography;

namespace Hashlib.NET.Common
{
    public interface IHashAlgorithm : ICryptoTransform, IDisposable
    {
        int HashSize { get; }
        byte[] Hash { get; }

        void Clear();

        byte[] ComputeHash(Stream inputStream);

        byte[] ComputeHash(byte[] buffer, int offset, int count);

        byte[] ComputeHash(byte[] buffer);

        void Initialize();
    }
}
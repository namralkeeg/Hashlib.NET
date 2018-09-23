namespace Hashlib.NET.Common
{
    public interface IKeyedHash : IHashAlgorithm
    {
        byte[] Key { get; set; }
    }
}
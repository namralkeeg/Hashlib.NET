namespace Hashlib.NET.Common
{
    internal interface IKeyedHash
    {
        byte[] Key { get; set; }
    }
}
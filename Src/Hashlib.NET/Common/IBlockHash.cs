namespace Hashlib.NET.Common
{
    /// <summary>
    /// An Interface for hash algorithms that use a block algorithm.
    /// </summary>
    internal interface IBlockHash
    {
        /// <summary>
        /// The size in bytes of each block that's processed at once.
        /// </summary>
        int BlockSize { get; }
    }
}
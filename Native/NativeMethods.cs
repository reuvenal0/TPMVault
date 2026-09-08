using System.Runtime.InteropServices;

namespace TPMVault.Native;

/// <summary>
/// Native Windows CNG functions and structures required by TPMVault.
/// </summary>
internal static class NativeMethods
{
    public const int NteNoMoreItems =
        unchecked((int)0x8009002A);

    // Windows CNG attestation constants from ncrypt.h.
    public const int NcryptClaimPlatform =
        0x00010000;

    public const int NcryptBufferVersion =
        0;

    public const int NcryptBufferTpmPlatformClaimPcrMask =
        80;

    public const int NcryptBufferTpmPlatformClaimNonce =
        81;

    [StructLayout(LayoutKind.Sequential)]
    internal struct NCryptKeyName
    {
        public IntPtr Name;
        public IntPtr Algorithm;
        public uint LegacyKeySpec;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NCryptBuffer
    {
        public int BufferSize;
        public int BufferType;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NCryptBufferDesc
    {
        public int Version;
        public int BufferCount;
        public IntPtr Buffers;
    }

    [DllImport(
        "ncrypt.dll",
        CharSet = CharSet.Unicode)]
    internal static extern int NCryptOpenStorageProvider(
        out IntPtr providerHandle,
        string providerName,
        uint flags);

    [DllImport(
        "ncrypt.dll",
        CharSet = CharSet.Unicode)]
    internal static extern int NCryptEnumKeys(
        IntPtr providerHandle,
        string? scope,
        out IntPtr keyName,
        ref IntPtr enumState,
        uint flags);

    [DllImport("ncrypt.dll")]
    internal static extern int NCryptFreeBuffer(
        IntPtr buffer);

    [DllImport("ncrypt.dll")]
    internal static extern int NCryptFreeObject(
        IntPtr handle);

    [DllImport("ncrypt.dll")]
    internal static extern int NCryptCreateClaim(
        IntPtr subjectKey,
        IntPtr authorityKey,
        int claimType,
        ref NCryptBufferDesc parameterList,
        byte[]? claimBlob,
        int claimBlobSize,
        out int resultSize,
        int flags);
}

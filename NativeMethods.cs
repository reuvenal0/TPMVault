using System.Runtime.InteropServices;

namespace TPMVault;

/// <summary>
/// Native Windows CNG functions required for key enumeration.
/// </summary>
internal static class NativeMethods
{
    public const int NteNoMoreItems =
        unchecked((int)0x8009002A);

    [StructLayout(LayoutKind.Sequential)]
    internal struct NCryptKeyName
    {
        public IntPtr Name;
        public IntPtr Algorithm;
        public uint LegacyKeySpec;
        public uint Flags;
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
}

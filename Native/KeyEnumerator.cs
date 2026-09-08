using TPMVault.Crypto;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TPMVault.Native;

/// <summary>
/// Enumerates persistent keys from a Windows CNG key storage provider.
/// </summary>
public sealed class KeyEnumerator
{
    public IReadOnlyList<StoredKeyInfo> Enumerate(
        CngProvider provider)
    {
        var keys =
            new List<StoredKeyInfo>();

        IntPtr providerHandle =
            IntPtr.Zero;

        IntPtr enumState =
            IntPtr.Zero;

        int status =
            NativeMethods.NCryptOpenStorageProvider(
                out providerHandle,
                provider.Provider,
                0);

        if (status != 0)
        {
            throw new CryptographicException(
                $"Could not open provider. Error: 0x{status:X8}");
        }

        try
        {
            while (true)
            {
                IntPtr keyInfoPointer =
                    IntPtr.Zero;

                status =
                    NativeMethods.NCryptEnumKeys(
                        providerHandle,
                        null,
                        out keyInfoPointer,
                        ref enumState,
                        0);

                if (status ==
                    NativeMethods.NteNoMoreItems)
                {
                    break;
                }

                if (status != 0)
                {
                    throw new CryptographicException(
                        $"Key enumeration failed. Error: 0x{status:X8}");
                }

                try
                {
                    NativeMethods.NCryptKeyName nativeKey =
                        Marshal.PtrToStructure<
                            NativeMethods.NCryptKeyName>(
                                keyInfoPointer);

                    string name =
                        Marshal.PtrToStringUni(
                            nativeKey.Name)
                        ?? "<unknown>";

                    string algorithm =
                        Marshal.PtrToStringUni(
                            nativeKey.Algorithm)
                        ?? "<unknown>";

                    keys.Add(
                        new StoredKeyInfo(
                            name,
                            algorithm));
                }
                finally
                {
                    if (keyInfoPointer != IntPtr.Zero)
                    {
                        NativeMethods.NCryptFreeBuffer(
                            keyInfoPointer);
                    }
                }
            }
        }
        finally
        {
            if (enumState != IntPtr.Zero)
            {
                NativeMethods.NCryptFreeBuffer(
                    enumState);
            }

            if (providerHandle != IntPtr.Zero)
            {
                NativeMethods.NCryptFreeObject(
                    providerHandle);
            }
        }

        return keys;
    }
}

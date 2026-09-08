using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TPMVault;

/// <summary>
/// Creates a TPM platform claim containing PCR state and a fresh nonce.
/// </summary>
public sealed class AttestationService
{
    private const int NonceSizeBytes = 32;

    // Select PCR indexes 0 through 23.
    private const uint AllPcrsMask = 0x00FFFFFF;

    public AttestationResult CreatePlatformClaim(
        CngKey attestationKey)
    {
        if (attestationKey.Provider !=
            CngProvider.MicrosoftPlatformCryptoProvider)
        {
            throw new InvalidOperationException(
                "TPM platform attestation requires a Platform Crypto Provider key.");
        }

        byte[] nonce =
            RandomNumberGenerator.GetBytes(
                NonceSizeBytes);

        byte[] pcrMask =
            BitConverter.GetBytes(
                AllPcrsMask);

        GCHandle nonceHandle =
            default;

        GCHandle pcrMaskHandle =
            default;

        IntPtr nativeBuffers =
            IntPtr.Zero;

        // CngKey.Handle returns a new duplicate on each access. Keep the
        // same duplicate alive for both native calls and release it once.
        using var safeKeyHandle = attestationKey.Handle;

        bool keyHandleAddedRef =
            false;

        try
        {
            // Pin managed data passed to the native CNG API.
            nonceHandle = GCHandle.Alloc(
                nonce,
                GCHandleType.Pinned);

            pcrMaskHandle = GCHandle.Alloc(
                pcrMask,
                GCHandleType.Pinned);

            NativeMethods.NCryptBuffer[] buffers =
            [
                new NativeMethods.NCryptBuffer
                {
                    BufferSize = pcrMask.Length,
                    BufferType =
                        NativeMethods
                            .NcryptBufferTpmPlatformClaimPcrMask,
                    Buffer =
                        pcrMaskHandle.AddrOfPinnedObject()
                },

                new NativeMethods.NCryptBuffer
                {
                    BufferSize = nonce.Length,
                    BufferType =
                        NativeMethods
                            .NcryptBufferTpmPlatformClaimNonce,
                    Buffer =
                        nonceHandle.AddrOfPinnedObject()
                }
            ];

            int nativeBufferSize =
                Marshal.SizeOf<
                    NativeMethods.NCryptBuffer>();

            nativeBuffers =
                Marshal.AllocHGlobal(
                    nativeBufferSize *
                    buffers.Length);

            // Marshal the NCryptBuffer array into contiguous native memory.
            for (int i = 0;
                 i < buffers.Length;
                 i++)
            {
                IntPtr destination =
                    IntPtr.Add(
                        nativeBuffers,
                        i * nativeBufferSize);

                Marshal.StructureToPtr(
                    buffers[i],
                    destination,
                    false);
            }

            var descriptor =
                new NativeMethods.NCryptBufferDesc
                {
                    Version =
                        NativeMethods
                            .NcryptBufferVersion,
                    BufferCount =
                        buffers.Length,
                    Buffers =
                        nativeBuffers
                };

            safeKeyHandle.DangerousAddRef(
                ref keyHandleAddedRef);

            IntPtr keyHandle =
                safeKeyHandle
                    .DangerousGetHandle();

            // First call retrieves the required output size.
            int status =
                NativeMethods.NCryptCreateClaim(
                    keyHandle,
                    IntPtr.Zero,
                    NativeMethods.NcryptClaimPlatform,
                    ref descriptor,
                    null,
                    0,
                    out int requiredSize,
                    0);

            if (status != 0)
            {
                return
                    AttestationResult.Failed(
                        status);
            }

            if (requiredSize <= 0)
            {
                throw new CryptographicException(
                    "Windows returned an invalid attestation claim size.");
            }

            byte[] claim =
                new byte[requiredSize];

            // Second call creates the actual binary claim.
            status =
                NativeMethods.NCryptCreateClaim(
                    keyHandle,
                    IntPtr.Zero,
                    NativeMethods.NcryptClaimPlatform,
                    ref descriptor,
                    claim,
                    claim.Length,
                    out int bytesWritten,
                    0);

            if (status != 0)
            {
                CryptographicOperations.ZeroMemory(
                    claim);

                return
                    AttestationResult.Failed(
                        status);
            }

            if (bytesWritten <= 0 ||
                bytesWritten > claim.Length)
            {
                CryptographicOperations.ZeroMemory(
                    claim);

                throw new CryptographicException(
                    "Windows returned an invalid attestation claim length.");
            }

            if (bytesWritten != claim.Length)
            {
                Array.Resize(
                    ref claim,
                    bytesWritten);
            }

            // Keep a copy of the nonce so the caller can later verify freshness.
            byte[] nonceCopy =
                nonce.ToArray();

            return
                AttestationResult.Succeeded(
                    claim,
                    nonceCopy);
        }
        finally
        {
            if (keyHandleAddedRef)
            {
                safeKeyHandle
                    .DangerousRelease();
            }

            if (nativeBuffers !=
                IntPtr.Zero)
            {
                Marshal.FreeHGlobal(
                    nativeBuffers);
            }

            if (nonceHandle.IsAllocated)
            {
                nonceHandle.Free();
            }

            if (pcrMaskHandle.IsAllocated)
            {
                pcrMaskHandle.Free();
            }

            CryptographicOperations.ZeroMemory(
                nonce);

            CryptographicOperations.ZeroMemory(
                pcrMask);
        }
    }
}

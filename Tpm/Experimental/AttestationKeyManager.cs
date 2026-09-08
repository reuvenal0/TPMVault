using System.Security.Cryptography;

namespace TPMVault.Tpm.Experimental;

/// <summary>
/// Opens/creates an identity-style CNG key for the unsuccessful NCryptCreateClaim experiment.
/// </summary>
public sealed class AttestationKeyManager
{
    public const string AttestationKeyName =
        "TPMVault.AttestationKeyV1";

    private const int RsaKeySize = 2048;

    // NCRYPT_PCP_IDENTITY_KEY from ncrypt.h.
    private const int PcpIdentityKeyUsage = 0x00000008;

    public CngKey GetOrCreateKey()
    {
        CngProvider provider =
            CngProvider.MicrosoftPlatformCryptoProvider;

        if (CngKey.Exists(
            AttestationKeyName,
            provider))
        {
            return CngKey.Open(
                AttestationKeyName,
                provider);
        }

        var creationParameters =
            new CngKeyCreationParameters
            {
                Provider = provider,
                KeyUsage = CngKeyUsages.Signing
            };

        // Use RSA-2048 for the TPM identity key.
        creationParameters.Parameters.Add(
            new CngProperty(
                "Length",
                BitConverter.GetBytes(RsaKeySize),
                CngPropertyOptions.Persist));

        // Mark this key as a TPM identity/attestation key.
        creationParameters.Parameters.Add(
            new CngProperty(
                "PCP_KEY_USAGE_POLICY",
                BitConverter.GetBytes(PcpIdentityKeyUsage),
                CngPropertyOptions.Persist));

        return CngKey.Create(
            CngAlgorithm.Rsa,
            AttestationKeyName,
            creationParameters);
    }
}

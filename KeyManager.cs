using System.Security.Cryptography;

namespace TPMVault;

/// <summary>
/// Creates, opens, and deletes persistent Windows CNG keys.
/// </summary>
public sealed class KeyManager
{
    private const int RsaKeySize = 2048;

    public KeyConfiguration GetConfiguration(KeyBackend backend)
    {
        return backend switch
        {
            KeyBackend.Software => new KeyConfiguration(
                Backend: KeyBackend.Software,
                KeyName: "TPMVault.SoftwareKeyV2",
                Provider: CngProvider.MicrosoftSoftwareKeyStorageProvider,
                AllowPrivateKeyExport: true),

            KeyBackend.Tpm => new KeyConfiguration(
                Backend: KeyBackend.Tpm,
                KeyName: "TPMVault.TpmKeyV2",
                Provider: CngProvider.MicrosoftPlatformCryptoProvider,
                AllowPrivateKeyExport: false),

            _ => throw new ArgumentOutOfRangeException(
                nameof(backend),
                backend,
                "Unsupported key backend.")
        };
    }

    public CngKey GetOrCreateKey(KeyBackend backend)
    {
        KeyConfiguration configuration = GetConfiguration(backend);

        if (CngKey.Exists(
            configuration.KeyName,
            configuration.Provider))
        {
            return CngKey.Open(
                configuration.KeyName,
                configuration.Provider);
        }

        var creationParameters = new CngKeyCreationParameters
        {
            Provider = configuration.Provider,
            KeyUsage =
                CngKeyUsages.Signing |
                CngKeyUsages.Decryption
        };

        // Keep both backends on the same RSA key size for a fair comparison.
        creationParameters.Parameters.Add(
            new CngProperty(
                "Length",
                BitConverter.GetBytes(RsaKeySize),
                CngPropertyOptions.Persist));

        // The software key is exportable only to demonstrate the difference.
        if (configuration.AllowPrivateKeyExport)
        {
            creationParameters.ExportPolicy =
                CngExportPolicies.AllowExport |
                CngExportPolicies.AllowPlaintextExport;
        }

        return CngKey.Create(
            CngAlgorithm.Rsa,
            configuration.KeyName,
            creationParameters);
    }

    public bool DeleteKey(
        KeyBackend backend,
        string keyName)
    {
        KeyConfiguration configuration = GetConfiguration(backend);

        if (!CngKey.Exists(
            keyName,
            configuration.Provider))
        {
            return false;
        }

        using CngKey key = CngKey.Open(
            keyName,
            configuration.Provider);

        key.Delete();
        return true;
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TPMVault;

/// <summary>
/// Encrypts, stores, loads, and decrypts vault entries.
/// </summary>
public sealed class VaultService
{
    private const int VaultVersion = 1;
    private const int AesKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    private readonly string _vaultDirectory;

    public VaultService(string vaultDirectory = "vault")
    {
        _vaultDirectory = vaultDirectory;
    }

    public void StoreSecret(
        string name,
        string secret,
        CngKey key,
        KeyBackend backend)
    {
        ValidateSecretName(name);

        Directory.CreateDirectory(_vaultDirectory);

        byte[] plaintext =
            Encoding.UTF8.GetBytes(secret);

        byte[] aesKey =
            RandomNumberGenerator.GetBytes(AesKeySizeBytes);

        byte[] nonce =
            RandomNumberGenerator.GetBytes(NonceSizeBytes);

        byte[] tag =
            new byte[TagSizeBytes];

        byte[] ciphertext =
            new byte[plaintext.Length];

        byte[]? wrappedAesKey = null;

        try
        {
            // Encrypt the secret with a fresh AES-256-GCM key.
            using (var aes =
                new AesGcm(aesKey, TagSizeBytes))
            {
                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext,
                    tag);
            }

            using var rsa =
                new RSACng(key);

            // Protect the AES key with the selected persistent RSA key.
            wrappedAesKey = rsa.Encrypt(
                aesKey,
                RSAEncryptionPadding.OaepSHA256);

            var entry = new VaultEntry(
                Version: VaultVersion,
                Backend: backend.ToString(),
                WrappedAesKey: Convert.ToBase64String(wrappedAesKey),
                Nonce: Convert.ToBase64String(nonce),
                Tag: Convert.ToBase64String(tag),
                Ciphertext: Convert.ToBase64String(ciphertext));

            string json =
                JsonSerializer.Serialize(
                    entry,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

            File.WriteAllText(
                GetEntryPath(name),
                json,
                Encoding.UTF8);
        }
        finally
        {
            // Clear temporary plaintext key material after use.
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(plaintext);

            if (wrappedAesKey is not null)
            {
                CryptographicOperations.ZeroMemory(wrappedAesKey);
            }
        }
    }

    public string LoadSecret(
        string name,
        CngKey key,
        KeyBackend backend)
    {
        ValidateSecretName(name);

        string path =
            GetEntryPath(name);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"Vault entry not found: {name}");
        }

        string json =
            File.ReadAllText(path, Encoding.UTF8);

        VaultEntry entry =
            JsonSerializer.Deserialize<VaultEntry>(json)
            ?? throw new InvalidDataException(
                "Vault entry could not be parsed.");

        if (entry.Version != VaultVersion)
        {
            throw new InvalidDataException(
                $"Unsupported vault version: {entry.Version}");
        }

        if (!entry.Backend.Equals(
            backend.ToString(),
            StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"This entry was created with the '{entry.Backend}' backend.");
        }

        byte[] wrappedAesKey =
            Convert.FromBase64String(entry.WrappedAesKey);

        byte[] nonce =
            Convert.FromBase64String(entry.Nonce);

        byte[] tag =
            Convert.FromBase64String(entry.Tag);

        byte[] ciphertext =
            Convert.FromBase64String(entry.Ciphertext);

        byte[]? aesKey = null;
        byte[] plaintext =
            new byte[ciphertext.Length];

        try
        {
            using var rsa =
                new RSACng(key);

            // Recover the AES key through the persistent RSA private key.
            aesKey = rsa.Decrypt(
                wrappedAesKey,
                RSAEncryptionPadding.OaepSHA256);

            using (var aes =
                new AesGcm(aesKey, TagSizeBytes))
            {
                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext);
            }

            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            if (aesKey is not null)
            {
                CryptographicOperations.ZeroMemory(aesKey);
            }

            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(wrappedAesKey);
        }
    }

    private string GetEntryPath(string name)
    {
        return Path.Combine(
            _vaultDirectory,
            $"{name}.vault");
    }

    private static void ValidateSecretName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException(
                "Secret name cannot be empty.",
                nameof(name));
        }

        if (name.IndexOfAny(
            Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException(
                "Secret name contains invalid file name characters.",
                nameof(name));
        }
    }
}

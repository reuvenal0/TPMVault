using System.Text.Json;
using System.Text.Json.Serialization;
using TPMVault.Configuration;

namespace TPMVault.Vault;

/// <summary>Validates the version-1 encrypted Vault format before cryptographic operations.</summary>
public static class VaultEntrySerializer
{
    public const int MaximumSecretBytes = 1024 * 1024;
    public const int MaximumFileBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false
    };

    public static string Serialize(VaultEntry entry, KeyBackend backend)
    {
        Validate(entry, backend);
        return JsonSerializer.Serialize(entry, Options);
    }

    public static VaultEntry Deserialize(string json, KeyBackend backend)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaximumFileBytes)
            throw new InvalidDataException("Vault JSON is empty or exceeds the 2 MiB limit.");
        VaultEntry entry;
        try
        {
            entry = JsonSerializer.Deserialize<VaultEntry>(json, Options)
                ?? throw new InvalidDataException("Vault JSON must contain an entry object.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Invalid Vault JSON: check required fields, types, and duplicate properties.", ex);
        }
        Validate(entry, backend);
        return entry;
    }

    private static void Validate(VaultEntry entry, KeyBackend backend)
    {
        if (!Enum.IsDefined(backend)) throw new ArgumentException("Unsupported key backend.");
        if (entry.Version != 1) throw new InvalidDataException($"Unsupported Vault version: {entry.Version}.");
        if (string.IsNullOrEmpty(entry.Backend)) throw new InvalidDataException("Missing Vault backend.");
        if (!string.Equals(entry.Backend, backend.ToString(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Vault backend does not match the requested backend.");
        Decode(entry.WrappedAesKey, "wrapped AES key", 256);
        Decode(entry.Nonce, "nonce", 12);
        Decode(entry.Tag, "authentication tag", 16);
        // Empty plaintext is supported by GCM, but the ciphertext field must still be present.
        Decode(entry.Ciphertext, "ciphertext", null);
    }

    private static void Decode(string? value, string field, int? expectedLength)
    {
        if (value is null) throw new InvalidDataException($"Missing Vault {field}.");
        if (value.Length > MaximumFileBytes) throw new InvalidDataException($"Vault {field} is too large.");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(value); }
        catch (FormatException ex) { throw new InvalidDataException($"Invalid Base64 in Vault {field}.", ex); }
        if (expectedLength.HasValue && bytes.Length != expectedLength.Value)
            throw new InvalidDataException($"Vault {field} must contain {expectedLength.Value} bytes.");
        if (bytes.Length > MaximumSecretBytes) throw new InvalidDataException("Vault ciphertext exceeds 1 MiB.");
    }
}

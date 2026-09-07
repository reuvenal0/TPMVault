namespace TPMVault;

/// <summary>
/// Represents the encrypted data stored on disk for a single secret.
/// </summary>
public sealed record VaultEntry(
    int Version,
    string Backend,
    string WrappedAesKey,
    string Nonce,
    string Tag,
    string Ciphertext);

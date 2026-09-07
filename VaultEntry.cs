namespace TPMVault;

/// <summary>
/// Represents the encrypted payload stored on disk for one secret.
/// </summary>
public sealed record VaultEntry(
    int Version,
    string Backend,
    string WrappedAesKey,
    string Nonce,
    string Tag,
    string Ciphertext);

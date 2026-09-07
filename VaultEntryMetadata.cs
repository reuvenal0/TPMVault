namespace TPMVault;

/// <summary>
/// Contains safe metadata about a vault entry without exposing its secret.
/// </summary>
public sealed record VaultEntryMetadata(
    string Name,
    string Backend,
    int Version,
    int CiphertextBytes,
    int WrappedKeyBytes,
    int NonceBytes,
    int TagBytes);

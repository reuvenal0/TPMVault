namespace TPMVault;

/// <summary>
/// Represents a persisted key discovered in a CNG provider.
/// </summary>
public sealed record StoredKeyInfo(
    string Name,
    string Algorithm);

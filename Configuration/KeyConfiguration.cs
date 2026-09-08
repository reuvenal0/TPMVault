using System.Security.Cryptography;

namespace TPMVault.Configuration;

/// <summary>
/// Holds the Windows CNG configuration for a key backend.
/// </summary>
public sealed record KeyConfiguration(
    KeyBackend Backend,
    string KeyName,
    CngProvider Provider,
    bool AllowPrivateKeyExport);

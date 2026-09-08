namespace TPMVault;

/// <summary>Portable version-1 schema. All binary fields are Base64, never runtime objects.</summary>
public sealed record TpmQuoteEvidenceFile
{
    public required string Format { get; init; }
    public required int Version { get; init; }
    public required string HashAlgorithm { get; init; }
    public required uint[] PcrIndexes { get; init; }
    public required Dictionary<uint, string> PcrValues { get; init; }
    public required string Nonce { get; init; }
    public required string AttestationFormat { get; init; }
    public required string Attestation { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required string Signature { get; init; }
    public required string PublicKeyFormat { get; init; }
    public required string PublicKey { get; init; }
}

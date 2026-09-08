using Tpm2Lib;

namespace TPMVault;

/// <summary>In-memory local evidence. No private key or persistent handle is retained.</summary>
public sealed record TpmQuoteEvidence(
    byte[] Nonce,
    IReadOnlyDictionary<uint, string> PcrValues,
    Attest Attestation,
    ISignatureUnion Signature,
    TpmPublic PublicKey);

public sealed record TpmQuoteCheck(string Name, bool Valid, string? Error = null);

public sealed record TpmQuoteVerificationResult(IReadOnlyList<TpmQuoteCheck> Checks)
{
    public bool Verified => Checks.Count == 5 && Checks.All(check => check.Valid);
}

namespace TPMVault;

/// <summary>
/// Represents the result of a TPM platform attestation request.
/// </summary>
public sealed record AttestationResult(
    bool Success,
    byte[]? Claim,
    byte[]? Nonce,
    int Status)
{
    public static AttestationResult Succeeded(
        byte[] claim,
        byte[] nonce)
    {
        return new AttestationResult(
            Success: true,
            Claim: claim,
            Nonce: nonce,
            Status: 0);
    }

    public static AttestationResult Failed(
        int status)
    {
        return new AttestationResult(
            Success: false,
            Claim: null,
            Nonce: null,
            Status: status);
    }
}

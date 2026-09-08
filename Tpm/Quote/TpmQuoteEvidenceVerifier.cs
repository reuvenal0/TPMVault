using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace TPMVault.Tpm.Quote;

public sealed record TpmQuoteEvidenceVerificationResult(IReadOnlyList<TpmQuoteCheck> Checks)
{
    public bool Verified => Checks.Count == 11 && Checks.All(c => c.Valid);
}

/// <summary>Checks embedded-key consistency only. No TPM device or trusted identity is consulted.</summary>
public sealed class TpmQuoteEvidenceVerifier
{
    private const int MaximumEvidenceBytes = 65536;

    public TpmQuoteEvidenceVerificationResult VerifyFile(string path)
    {
        string safePath = new TpmQuoteEvidenceSerializer().ValidateInputPath(path);
        using var stream = new FileStream(safePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaximumEvidenceBytes)
            throw new InvalidDataException("Evidence file exceeds the 64 KiB limit.");
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true));
        return VerifyJson(reader.ReadToEnd());
    }

    public TpmQuoteEvidenceVerificationResult VerifyJson(string json)
    {
        var checks = new List<TpmQuoteCheck>();
        bool Check(string name, Action action)
        {
            try { action(); checks.Add(new(name, true)); return true; }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { checks.Add(new(name, false, ex.Message)); return false; }
        }
        static void Require(bool valid, string message)
        { if (!valid) throw new InvalidDataException(message); }

        TpmQuoteEvidenceFile? file = null;
        if (!Check("Format", () =>
        {
            Require(json.Length <= MaximumEvidenceBytes, "Evidence exceeds the 64 KiB limit.");
            file = TpmQuoteEvidenceSerializer.DeserializeSchema(json);
            Require(file.Format == "TPMVault.TpmQuote" && file.Version == 1,
                "Unsupported evidence format/version; expected TPMVault.TpmQuote version 1.");
            Require(file.AttestationFormat == "TPMS_ATTEST", "Unsupported attestation encoding.");
        })) return new(checks);
        var f = file!;
        Check("Hash algorithm", () => Require(f.HashAlgorithm == "SHA-256", "Only SHA-256 is supported."));

        byte[] nonce = [], attestationBytes = [], signature = [], publicKey = [];
        if (!Check("Binary encoding", () =>
        {
            nonce = TpmQuoteEvidenceSerializer.Decode(f.Nonce, "nonce", 32);
            attestationBytes = TpmQuoteEvidenceSerializer.Decode(f.Attestation, "attestation");
            signature = TpmQuoteEvidenceSerializer.Decode(f.Signature, "signature", 256);
            publicKey = TpmQuoteEvidenceSerializer.Decode(f.PublicKey, "publicKey");
        })) return new(checks);

        using RSA rsa = RSA.Create();
        bool keyValid = Check("Public key", () =>
        {
            Require(f.PublicKeyFormat == "SubjectPublicKeyInfo-DER", "Expected DER SubjectPublicKeyInfo.");
            rsa.ImportSubjectPublicKeyInfo(publicKey, out int consumed);
            Require(consumed == publicKey.Length && rsa.KeySize == 2048,
                "Expected exactly one RSA-2048 SubjectPublicKeyInfo value.");
            Require(publicKey.AsSpan().SequenceEqual(rsa.ExportSubjectPublicKeyInfo()),
                "Public key must use the canonical DER SubjectPublicKeyInfo encoding exported by version 1.");
        });
        Attest? attestation = null;
        Check("Attestation parse", () =>
        {
            var parser = new Marshaller(attestationBytes, DataRepresentation.Tpm);
            attestation = parser.Get<Attest>();
            Require(parser.GetGetPos() == attestationBytes.Length, "Trailing data after TPMS_ATTEST.");
        });
        Check("Magic", () => Require(attestation?.magic == Generated.Value, "Invalid TPM-generated magic."));
        Check("Attestation type", () => Require(attestation?.type == TpmSt.AttestQuote &&
            attestation.attested is QuoteInfo, "Attestation is not a TPM Quote."));
        Check("Nonce", () => Require(attestation?.extraData is not null &&
            CryptographicOperations.FixedTimeEquals(nonce, attestation.extraData), "Quoted nonce does not match evidence nonce."));
        var quote = attestation?.attested as QuoteInfo;
        bool selectionValid = Check("PCR selection", () =>
        {
            uint[] expected = [0, 2, 4, 7];
            Require(f.PcrIndexes is not null && f.PcrIndexes.SequenceEqual(expected) &&
                f.PcrValues is not null && f.PcrValues.Keys.Order().SequenceEqual(expected),
                "Version 1 requires exactly PCRs 0, 2, 4, 7 and their values.");
            Require(quote?.pcrSelect is { Length: 1 } && quote.pcrSelect[0].hash == TpmAlgId.Sha256 &&
                quote.pcrSelect[0].GetSelectedPcrs().SequenceEqual(expected),
                "Quoted selection does not match the evidence SHA-256 PCR selection.");
        });
        Check("PCR digest", () =>
        {
            Require(selectionValid && f.HashAlgorithm == "SHA-256", "PCR digest requires a valid SHA-256 selection.");
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            // TPM Quote hashes raw PCR values in selection order, without TPM2B length prefixes.
            foreach (uint index in f.PcrIndexes)
                hash.AppendData(TpmQuoteEvidenceSerializer.Decode(f.PcrValues[index], $"PCR {index}", 32));
            Require(quote?.pcrDigest is not null &&
                CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), quote.pcrDigest),
                "Quoted PCR digest does not match the serialized PCR values.");
        });
        Check("Signature", () =>
        {
            Require(keyValid, "Signature cannot be checked without a valid public key.");
            Require(f.SignatureAlgorithm == "RSASSA-PKCS1-v1_5" && f.HashAlgorithm == "SHA-256",
                "Only RSASSA-PKCS1-v1_5 with SHA-256 is supported.");
            // Verify the exact bytes from the file, never a re-serialized replacement.
            Require(rsa.VerifyData(attestationBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "Signature does not validate under the embedded public key.");
        });
        return new(checks);
    }
}

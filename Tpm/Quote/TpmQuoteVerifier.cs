using System.Security.Cryptography;
using Tpm2Lib;

namespace TPMVault.Tpm.Quote;

/// <summary>Local verification only; does not establish certificate or device trust.</summary>
public static class TpmQuoteVerifier
{
    public static TpmQuoteVerificationResult Verify(TpmQuoteEvidence evidence, byte[] expectedNonce)
    {
        uint[] expectedPcrs = [0, 2, 4, 7];
        var checks = new List<TpmQuoteCheck>();

        // Run separately: TpmPublic.VerifyQuote short-circuits at its first failure.
        Check("Attestation type", () => evidence.Attestation is not null &&
            evidence.Attestation.magic == Generated.Value &&
            evidence.Attestation.type == TpmSt.AttestQuote &&
            evidence.Attestation.attested is QuoteInfo,
            "Malformed Quote: wrong attestation type or TPM-generated magic.");

        Check("Nonce", () => expectedNonce is { Length: 32 } &&
            evidence.Attestation.extraData is { Length: 32 } &&
            CryptographicOperations.FixedTimeEquals(expectedNonce, evidence.Attestation.extraData),
            "Nonce mismatch.");

        Check("PCR selection", () => evidence.Attestation.attested is QuoteInfo quote &&
            quote.pcrSelect is { Length: 1 } &&
            quote.pcrSelect[0].hash == TpmAlgId.Sha256 &&
            quote.pcrSelect[0].GetSelectedPcrs().SequenceEqual(expectedPcrs),
            "Quote must cover exactly SHA-256 PCRs 0, 2, 4, 7.");

        Check("PCR digest", () =>
        {
            if (evidence.Attestation.attested is not QuoteInfo quote ||
                quote.pcrDigest is not { Length: 32 } ||
                !evidence.PcrValues.Keys.Order().SequenceEqual(expectedPcrs))
            {
                return false;
            }

            // Same digest rule as Microsoft's TpmPublic.VerifyQuote: hash the
            // concatenated raw PCR digests, with no TPM2B lengths or selection.
            // This is hashing application data, not encoding TPM command packets.
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (uint index in expectedPcrs)
            {
                byte[] value = Convert.FromHexString(evidence.PcrValues[index]);
                if (value.Length != 32) return false;
                hash.AppendData(value);
            }
            return CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), quote.pcrDigest);
        }, "PCR digest mismatch or invalid PCR snapshot; PCRs may have changed after Quote.");

        Check("Signature", () => evidence.PublicKey.type == TpmAlgId.Rsa &&
            evidence.Signature is SignatureRsassa { hash: TpmAlgId.Sha256 } &&
            evidence.PublicKey.VerifySignatureOverData(
                evidence.Attestation.GetTpmRepresentation(), evidence.Signature),
            "RSASSA-SHA256 signature verification failed.");

        return new TpmQuoteVerificationResult(checks.AsReadOnly());

        void Check(string name, Func<bool> verify, string failure)
        {
            try
            {
                bool valid = verify();
                checks.Add(new TpmQuoteCheck(name, valid, valid ? null : failure));
            }
            catch (Exception ex)
            {
                checks.Add(new TpmQuoteCheck(name, false,
                    $"{failure} {ex.GetType().Name}: {ex.Message}"));
            }
        }
    }
}

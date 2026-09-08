using System.Security.Cryptography;
using Tpm2Lib;

namespace TPMVault.Tpm.Quote;

/// <summary>Creates an ephemeral Quote. Does not persist keys or alter PCRs.</summary>
public sealed class TpmQuoteService
{
    public TpmQuoteEvidence CreateQuote()
    {
        using var device = new TpmDeviceService();
        Tpm2 tpm = device.Commands;
        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        TpmHandle? key = null;
        Exception? failure = null;
        bool quoteCreated = false;
        string stage = "RSA-2048 / RSASSA-SHA256 algorithm support (TestParms)";

        try
        {
            var rsa = new RsaParms(new SymDefObject(),
                new SchemeRsassa(TpmAlgId.Sha256), 2048, 0);
            tpm.TestParms(rsa);
            var template = new TpmPublic(TpmAlgId.Sha256,
                ObjectAttr.Sign | ObjectAttr.Restricted |
                ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
                ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth,
                Array.Empty<byte>(), rsa, new Tpm2bPublicKeyRsa());

            stage = "transient quoting key creation (CreatePrimary, null hierarchy)";
            // The null hierarchy needs no owner/endorsement authorization. This
            // returned object is transient; EvictControl is never used.
            key = tpm.CreatePrimary(TpmRh.Null,
                new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
                template, Array.Empty<byte>(), Array.Empty<PcrSelection>(),
                out TpmPublic publicKey, out _, out _, out _);

            stage = "TPM2_Quote";
            Attest attestation = tpm.Quote(key, nonce,
                new SchemeRsassa(TpmAlgId.Sha256),
                [new PcrSelection(TpmAlgId.Sha256, new uint[] { 0, 2, 4, 7 })],
                out ISignatureUnion signature);
            quoteCreated = true;

            stage = "PCR read after Quote";
            // Preserve the existing partial-response and update-counter handling.
            // A PCR change between Quote and this read yields a digest mismatch.
            var pcrs = device.ReadSha256Pcrs();
            return new TpmQuoteEvidence(nonce, pcrs, attestation, signature, publicKey);
        }
        catch (Exception ex)
        {
            failure = new TpmQuoteException(stage, quoteCreated, ex);
            throw failure;
        }
        finally
        {
            if (key is not null)
            {
                try
                {
                    // Flush only the handle returned by this invocation's CreatePrimary.
                    tpm.FlushContext(key);
                }
                catch (Exception cleanupError)
                {
                    throw new TpmQuoteException("transient quoting key FlushContext", quoteCreated,
                        failure is null ? cleanupError : new AggregateException(failure, cleanupError));
                }
            }
        }
    }
}

public sealed class TpmQuoteException : Exception
{
    public bool QuoteCreated { get; }

    public TpmQuoteException(string stage, bool quoteCreated, Exception cause)
        : base($"{stage} failed: {cause.GetType().Name}: {cause.Message}" +
            (cause is TpmException tpmError
                ? $" TPM response: {tpmError.RawResponse} (0x{(uint)tpmError.RawResponse:X8})."
                : ""), cause)
    {
        QuoteCreated = quoteCreated;
    }
}

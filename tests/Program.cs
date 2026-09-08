using System.Security.Cryptography;
using Tpm2Lib;
using TPMVault;

// Synthetic, software-signed fixtures test the verifier, NOT hardware attestation.
using RSA rsa = RSA.Create(2048);
uint[] indexes = [0, 2, 4, 7];
byte[] nonce = RandomNumberGenerator.GetBytes(32);
byte[] pcrBytes = Enumerable.Range(0, 128).Select(i => (byte)i).ToArray();
var pcrs = indexes.Select((index, i) => (index, value: Convert.ToHexString(pcrBytes.AsSpan(i * 32, 32))))
    .ToDictionary(p => p.index, p => p.value);
var publicKey = new TpmPublic(TpmAlgId.Sha256, ObjectAttr.Sign,
    Array.Empty<byte>(), new RsaParms(new SymDefObject(), new SchemeRsassa(TpmAlgId.Sha256), 2048, 65537),
    new Tpm2bPublicKeyRsa(rsa.ExportParameters(false).Modulus));
int passed = 0;

TpmQuoteEvidence Fixture()
{
    var attest = new Attest(Generated.Value, Array.Empty<byte>(), nonce.ToArray(),
        new ClockInfo(), 0, new QuoteInfo(
            [new PcrSelection(TpmAlgId.Sha256, indexes)], SHA256.HashData(pcrBytes)));
    return Sign(new TpmQuoteEvidence(nonce.ToArray(), new Dictionary<uint, string>(pcrs),
        attest, new SignatureRsassa(), publicKey));
}

TpmQuoteEvidence Sign(TpmQuoteEvidence evidence) => evidence with
{
    Signature = new SignatureRsassa(TpmAlgId.Sha256,
        rsa.SignData(evidence.Attestation.GetTpmRepresentation(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
};

void Assert(bool condition, string name)
{
    if (!condition) throw new Exception($"FAILED: {name}");
    Console.WriteLine($"PASS: {name}");
    passed++;
}

void Reject(TpmQuoteEvidence evidence, string check, bool signatureValid = true)
{
    var result = TpmQuoteVerifier.Verify(evidence, nonce);
    Assert(!result.Verified && !result.Checks.Single(c => c.Name == check).Valid &&
        result.Checks.Single(c => c.Name == "Signature").Valid == signatureValid, check);
}

var valid = Fixture();
Assert(TpmQuoteVerifier.Verify(valid, nonce).Verified, "valid synthetic evidence");
Assert(publicKey.VerifyQuote(TpmAlgId.Sha256,
    [new PcrSelection(TpmAlgId.Sha256, indexes)],
    indexes.Select(i => new Tpm2bDigest(Convert.FromHexString(pcrs[i]))).ToArray(),
    nonce, valid.Attestation, valid.Signature), "Microsoft VerifyQuote agrees on valid fixture");

var changed = Fixture();
changed.Attestation.extraData[0] ^= 1;
Reject(Sign(changed), "Nonce"); // Valid signature must not excuse the wrong nonce.

changed = Fixture();
changed.Attestation.magic = (Generated)0;
Reject(Sign(changed), "Attestation type");

changed = Fixture();
changed.Attestation.attested = new CertifyInfo(Array.Empty<byte>(), Array.Empty<byte>());
Reject(Sign(changed), "Attestation type");

changed = Fixture();
((QuoteInfo)changed.Attestation.attested).pcrSelect = [new PcrSelection(TpmAlgId.Sha256, new uint[] { 0, 2, 4 })];
Reject(Sign(changed), "PCR selection");

changed = Fixture();
((QuoteInfo)changed.Attestation.attested).pcrSelect = [new PcrSelection(TpmAlgId.Sha1, indexes)];
Reject(Sign(changed), "PCR selection");

changed = Fixture();
((QuoteInfo)changed.Attestation.attested).pcrDigest[0] ^= 1;
Reject(Sign(changed), "PCR digest");

changed = Fixture();
var alteredPcrs = new Dictionary<uint, string>(pcrs) { [7] = new string('F', 64) };
Reject(changed with { PcrValues = alteredPcrs }, "PCR digest");
Reject(changed with { PcrValues = new Dictionary<uint, string>() }, "PCR digest");

changed = Fixture();
((SignatureRsassa)changed.Signature).sig[0] ^= 1;
Reject(changed, "Signature", signatureValid: false);

changed = Fixture();
((QuoteInfo)changed.Attestation.attested).pcrSelect =
    [new PcrSelection(TpmAlgId.Sha256, new byte[] { 0x95, 0, 0, 0 })];
Assert(TpmQuoteVerifier.Verify(Sign(changed), nonce).Verified, "equivalent PCR bitmap with zero padding");
Console.WriteLine($"{passed} software-only checks passed. No TPM connection or key was created.");

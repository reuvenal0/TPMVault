using System.Security.Cryptography;
using System.Text.Json.Nodes;
using TPMVault;
using Tpm2Lib;

internal static class QuoteEvidenceVerificationChecks
{
    public static void Run(Func<TpmQuoteEvidence> fixture, byte[] nonce,
        Func<TpmQuoteEvidence, TpmQuoteEvidence> sign, Action<bool, string> assert)
    {
        var serializer = new TpmQuoteEvidenceSerializer();
        var verifier = new TpmQuoteEvidenceVerifier();
        string valid = serializer.SerializeVerified(fixture(), nonce);
        assert(verifier.VerifyJson(valid).Verified, "offline: valid exported synthetic evidence");
        JsonObject Json() => JsonNode.Parse(valid)!.AsObject();
        void Reject(JsonObject json, string check)
        {
            var result = verifier.VerifyJson(json.ToJsonString());
            assert(!result.Verified && result.Checks.Any(c => c.Name == check && !c.Valid), "offline: rejects " + check);
        }
        void Change(string field, JsonNode? value, string check)
        { var json = Json(); json[field] = value; Reject(json, check); }
        void AlterAttestation(Action<Attest> alter, string check)
        {
            var evidence = fixture();
            alter(evidence.Attestation);
            evidence = sign(evidence);
            var json = Json();
            json["attestation"] = Convert.ToBase64String(evidence.Attestation.GetTpmRepresentation());
            json["signature"] = Convert.ToBase64String(((SignatureRsassa)evidence.Signature).sig);
            Reject(json, check);
            assert(verifier.VerifyJson(json.ToJsonString()).Checks.Single(c => c.Name == "Signature").Valid,
                "offline: valid signature does not excuse " + check);
        }
        Change("nonce", Convert.ToBase64String(new byte[32]), "Nonce");
        AlterAttestation(a => a.magic = (Generated)0, "Magic");
        AlterAttestation(a => a.attested = new CertifyInfo([], []), "Attestation type");
        AlterAttestation(a => ((QuoteInfo)a.attested).pcrSelect =
            [new PcrSelection(TpmAlgId.Sha256, new uint[] { 0, 2, 4 })], "PCR selection");
        AlterAttestation(a => ((QuoteInfo)a.attested).pcrDigest[0] ^= 1, "PCR digest");
        Change("pcrIndexes", new JsonArray(0, 2, 4, 8), "PCR selection");
        var pcr = Json(); pcr["pcrValues"]!["7"] = Convert.ToBase64String(new byte[32]); Reject(pcr, "PCR digest");
        Change("signature", Convert.ToBase64String(new byte[256]), "Signature");
        Change("publicKey", Convert.ToBase64String(new byte[32]), "Public key");
        using RSA other = RSA.Create(2048);
        Change("publicKey", Convert.ToBase64String(other.ExportSubjectPublicKeyInfo()), "Signature");
        foreach (string field in new[] { "nonce", "attestation", "signature", "publicKey" })
            Change(field, "!!!", "Binary encoding");
        pcr = Json(); pcr["pcrValues"]!["7"] = "!!!"; Reject(pcr, "PCR digest");
        Change("version", 999, "Format");
        Change("hashAlgorithm", "SHA-1", "Hash algorithm");
        Change("signatureAlgorithm", "RSA-PSS", "Signature");
        Change("publicKeyFormat", "PKCS1", "Public key");
        Change("attestation", Convert.ToBase64String(new byte[] { 1, 2 }), "Attestation parse");
        Change("attestation", Convert.ToBase64String(
            Convert.FromBase64String(Json()["attestation"]!.GetValue<string>()).Concat(new byte[] { 0 }).ToArray()), "Attestation parse");
        foreach (string field in Json().Select(p => p.Key).ToArray())
        {
            var missing = Json(); missing.Remove(field); Reject(missing, "Format");
            var nil = Json(); nil[field] = null;
            assert(!verifier.VerifyJson(nil.ToJsonString()).Verified, "offline: rejects null " + field);
        }
        string root = Path.GetDirectoryName(serializer.ValidateOutputPath("offline-unused.json"))!;
        string directory = Path.Combine(root, "tests", "obj", "offline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "evidence.json");
        File.WriteAllText(path, valid);
        byte[] original = File.ReadAllBytes(path);
        assert(verifier.VerifyFile(path).Verified, "offline: reads repository-local file");
        assert(File.ReadAllBytes(path).SequenceEqual(original), "offline: evidence remains unchanged");
        foreach (string unsafePath in new[] { @"..\..\outside.json", @"\\server\share\evidence.json", "quote.json:stream", directory })
        {
            bool rejected = false;
            try { verifier.VerifyFile(unsafePath); }
            catch (Exception ex) when (ex is ArgumentException or IOException) { rejected = true; }
            assert(rejected, "offline: rejects unsafe input " + unsafePath);
        }
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            assert(new TpmVaultApp().Run(["verify-quote", path]) == 0, "offline CLI success exit code");
            assert(new TpmVaultApp().Run(["verify-quote"]) == 1, "offline CLI missing argument");
            assert(new TpmVaultApp().Run(["verify-quote", path, "extra"]) == 1, "offline CLI extra argument");
            var bad = Json(); bad["nonce"] = Convert.ToBase64String(new byte[32]);
            string badPath = Path.Combine(directory, "invalid.json");
            File.WriteAllText(badPath, bad.ToJsonString());
            assert(new TpmVaultApp().Run(["verify-quote", badPath]) == 1, "offline CLI failure exit code");
        }
        finally { Console.SetOut(previous); }
        assert(output.ToString().Contains("Quote evidence:    VERIFIED") && output.ToString().Split('\n')
            .Any(line => line.StartsWith("Nonce:") && line.Contains("FAILED:")),
            "offline CLI reports success and precise failed check");
    }
}

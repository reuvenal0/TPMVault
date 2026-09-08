using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tpm2Lib;
using TPMVault;

internal static class EvidenceSerializationChecks
{
    public static void Run(Func<TpmQuoteEvidence> fixture, byte[] nonce, Action<bool, string> assert)
    {
        var serializer = new TpmQuoteEvidenceSerializer();
        TpmQuoteEvidence evidence = fixture();
        string json = serializer.SerializeVerified(evidence, nonce);
        TpmQuoteEvidenceFile file = serializer.Deserialize(json);
        assert(file.Version == 1 && file.Format == "TPMVault.TpmQuote" &&
            file.PcrIndexes.SequenceEqual(new uint[] { 0, 2, 4, 7 }), "evidence schema");
        assert(Convert.FromBase64String(file.Nonce).SequenceEqual(nonce) &&
            Convert.FromBase64String(file.Attestation).SequenceEqual(evidence.Attestation.GetTpmRepresentation()) &&
            Convert.FromBase64String(file.Signature).SequenceEqual(((SignatureRsassa)evidence.Signature).sig) &&
            file.PcrValues.All(p => Convert.FromBase64String(p.Value).SequenceEqual(Convert.FromHexString(evidence.PcrValues[p.Key]))),
            "binary evidence serialization");

        string again = JsonSerializer.Serialize(file, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        assert(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(again)), "deserialization round-trip");
        using RSA publicRsa = RSA.Create();
        publicRsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(file.PublicKey), out int consumed);
        assert(consumed == Convert.FromBase64String(file.PublicKey).Length &&
            publicRsa.ExportParameters(false).Modulus!.SequenceEqual(((Tpm2bPublicKeyRsa)evidence.PublicKey.unique).buffer),
            "SPKI public-key round-trip");
        Reject(() => publicRsa.ExportParameters(true), "SPKI contains no private key");

        JsonObject Root() => JsonNode.Parse(json)!.AsObject();
        foreach (string name in new[] { "nonce", "attestation", "signature", "publicKey" })
        {
            var invalid = Root();
            invalid[name] = "not/base64!";
            Reject(() => serializer.Deserialize(invalid.ToJsonString()), $"malformed Base64: {name}");
        }
        var badPcr = Root();
        badPcr["pcrValues"]!["7"] = "!";
        Reject(() => serializer.Deserialize(badPcr.ToJsonString()), "malformed PCR Base64");
        var version = Root();
        version["version"] = 2;
        Reject(() => serializer.Deserialize(version.ToJsonString()), "unsupported version");
        foreach (string name in Root().Select(p => p.Key))
        {
            var missing = Root();
            missing.Remove(name);
            Reject(() => serializer.Deserialize(missing.ToJsonString()), $"missing required field: {name}");
            var nullField = Root();
            nullField[name] = null;
            Reject(() => serializer.Deserialize(nullField.ToJsonString()), $"null required field: {name}");
        }
        var extra = Root();
        extra["privateKey"] = "unexpected";
        Reject(() => serializer.Deserialize(extra.ToJsonString()), "unknown fields rejected");

        // Derive test locations from the serializer's anchored root, never the OS temp directory.
        string relativeDirectory = Path.Combine("tests", "obj", "evidence-" + Guid.NewGuid().ToString("N"));
        string root = Path.GetDirectoryName(serializer.ValidateOutputPath("unused-" + Guid.NewGuid().ToString("N") + ".json"))!;
        string testDirectory = Path.Combine(root, relativeDirectory);
        Directory.CreateDirectory(testDirectory);
        string output = Path.Combine(relativeDirectory, "quote.json");
        string fullOutput = serializer.ValidateOutputPath(output);
        assert(fullOutput == Path.Combine(testDirectory, "quote.json"), "repository-local relative path");
        assert(serializer.ValidateOutputPath(fullOutput) == fullOutput, "repository-local absolute path");
        foreach (string unsafePath in new[] { @"..\..\outside.json", root + "-sibling\\quote.json",
            @"\\?\C:\quote.json", @"vault\quote.json", @".git\quote.json", "quote.json:stream", "CON.json", "quote.json " })
            Reject(() => serializer.ValidateOutputPath(unsafePath), $"unsafe path rejected: {unsafePath}");

        string invalidOutput = Path.Combine(relativeDirectory, "invalid.json");
        byte[] wrongNonce = nonce.ToArray();
        wrongNonce[0] ^= 1;
        Reject(() => serializer.WriteVerified(evidence, wrongNonce, invalidOutput), "failed verification cannot export");
        assert(!File.Exists(Path.Combine(root, invalidOutput)), "failed verification creates no file");

        string saved = serializer.WriteVerified(evidence, nonce, output);
        assert(saved == fullOutput && JsonNode.DeepEquals(JsonNode.Parse(File.ReadAllText(saved)), JsonNode.Parse(json)),
            "verified evidence file written");
        Reject(() => serializer.WriteVerified(evidence, nonce, output), "existing-file rejection");
        assert(File.ReadAllText(saved) == json, "existing evidence unchanged");

        string racePath = serializer.ValidateOutputPath(Path.Combine(relativeDirectory, "appeared.json"));
        File.WriteAllText(racePath, "sentinel");
        Reject(() => serializer.WriteVerified(evidence, nonce, racePath), "target appearing after preflight rejected");
        assert(File.ReadAllText(racePath) == "sentinel", "newly existing file unchanged");

        foreach (string[] args in new[] { new[] { "quote", "--output" }, new[] { "quote", "--other", "q.json" },
            new[] { "quote", "--output", "" }, new[] { "quote", "--output", @"..\outside.json" },
            new[] { "quote", "--output", saved } })
        {
            TextWriter previous = Console.Out;
            using var captured = new StringWriter();
            int exit;
            try { Console.SetOut(captured); exit = new TpmVaultApp().Run(args); }
            finally { Console.SetOut(previous); }
            assert(exit == 1 && !captured.ToString().Contains("TBS"), "CLI rejects invalid output arguments before TPM access");
        }

        void Reject(Action action, string name)
        {
            bool rejected = false;
            try { action(); }
            catch (Exception ex) when (ex is ArgumentException or IOException or InvalidDataException or JsonException or CryptographicException or InvalidOperationException)
            { rejected = true; }
            assert(rejected, name);
        }
    }
}

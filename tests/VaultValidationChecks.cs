using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TPMVault;
using TPMVault.Configuration;
using TPMVault.Tpm.Quote;
using TPMVault.Vault;

namespace TPMVault.Tests;

internal static class VaultValidationChecks
{
    public static void Run(Action<bool, string> assert)
    {
        // Software-only hybrid-encryption fixture. RSA.Create creates no persistent CNG key.
        using RSA rsa = RSA.Create(2048);
        byte[] aesKey = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("synthetic test value");
        byte[] recovered = new byte[plaintext.Length];
        byte[]? unwrapped = null;
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            using (var aes = new AesGcm(aesKey, 16)) aes.Encrypt(nonce, plaintext, ciphertext, tag);
            var entry = new VaultEntry(1, "Software",
                Convert.ToBase64String(rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256)),
                Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(ciphertext));
            string json = VaultEntrySerializer.Serialize(entry, KeyBackend.Software);
            var parsed = VaultEntrySerializer.Deserialize(json, KeyBackend.Software);
            assert(parsed == entry, "Vault: valid serialization round-trip");
            unwrapped = rsa.Decrypt(Convert.FromBase64String(parsed.WrappedAesKey), RSAEncryptionPadding.OaepSHA256);
            using (var aes = new AesGcm(unwrapped, 16)) aes.Decrypt(
                Convert.FromBase64String(parsed.Nonce), Convert.FromBase64String(parsed.Ciphertext),
                Convert.FromBase64String(parsed.Tag), recovered);
            assert(recovered.SequenceEqual(plaintext), "Vault: hybrid encryption fixture round-trip");

            void Reject(Action action, string name)
            {
                bool rejected = false;
                try { action(); }
                catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException) { rejected = true; }
                assert(rejected, "Vault: " + name);
            }
            void Invalid(string value, string name) => Reject(
                () => VaultEntrySerializer.Deserialize(value, KeyBackend.Software), name);
            JsonObject Json() => JsonNode.Parse(json)!.AsObject();
            Invalid("{", "malformed JSON");
            Invalid("null", "null object");
            Invalid("[]", "wrong JSON shape");
            Invalid(json.Replace("\"Version\": 1", "\"Version\": 1, \"Version\": 1"), "duplicate field");
            foreach (string field in Json().Select(p => p.Key).ToArray())
            {
                var missing = Json(); missing.Remove(field); Invalid(missing.ToJsonString(), "missing " + field);
                var nil = Json(); nil[field] = null; Invalid(nil.ToJsonString(), "null " + field);
            }
            foreach (string field in new[] { "WrappedAesKey", "Nonce", "Tag", "Ciphertext" })
            {
                var invalid = Json(); invalid[field] = "!"; Invalid(invalid.ToJsonString(), "invalid Base64 " + field);
            }
            foreach (var item in new[] { ("WrappedAesKey", 255), ("Nonce", 11), ("Tag", 15) })
            {
                var invalid = Json(); invalid[item.Item1] = Convert.ToBase64String(new byte[item.Item2]);
                Invalid(invalid.ToJsonString(), "invalid length " + item.Item1);
            }
            var version = Json(); version["Version"] = 2; Invalid(version.ToJsonString(), "unsupported version");
            Reject(() => VaultEntrySerializer.Deserialize(json, KeyBackend.Tpm), "backend mismatch");
            Invalid(new string(' ', VaultEntrySerializer.MaximumFileBytes + 1), "oversized JSON");
            var oversized = Json(); oversized["Ciphertext"] = Convert.ToBase64String(new byte[VaultEntrySerializer.MaximumSecretBytes + 1]);
            Invalid(oversized.ToJsonString(), "oversized ciphertext");

            var evidencePaths = new TpmQuoteEvidenceSerializer();
            string root = Path.GetDirectoryName(evidencePaths.ValidateOutputPath("unused-vault-test.json"))!;
            string directory = Path.Combine(root, "tests", "obj", "vault-" + Guid.NewGuid().ToString("N"));
            string backendDirectory = Path.Combine(directory, "software");
            Directory.CreateDirectory(backendDirectory);
            string entryPath = Path.Combine(backendDirectory, "fixture.vault");
            File.WriteAllText(entryPath, json);
            var service = new VaultService(directory);
            Reject(() => service.ValidateStoreRequest("../invalid", "value", KeyBackend.Software),
                "write preflight rejects invalid names before key creation");
            Reject(() => service.ValidateStoreRequest("unused", new string('x', VaultEntrySerializer.MaximumSecretBytes + 1), KeyBackend.Software),
                "write preflight rejects oversized secrets before key creation");
            assert(service.Inspect(KeyBackend.Software, "fixture").NonceBytes == 12, "Vault: inspect without key access");
            assert(service.ListSecrets(KeyBackend.Software).SequenceEqual(new[] { "fixture" }), "Vault: list synthetic metadata");
            assert(File.ReadAllText(entryPath) == json, "Vault: read operations preserve file");
            foreach (string name in new[] { "..", "../escape", @"..\escape", "CON", "name:stream", "name.", "name " })
                Reject(() => service.Inspect(KeyBackend.Software, name), "unsafe name " + name);
            Reject(() => new VaultService(@"..\outside"), "outside Vault root");
            File.WriteAllText(Path.Combine(backendDirectory, "malformed.vault"), "{");
            Reject(() => service.Inspect(KeyBackend.Software, "malformed"), "controlled malformed file error");

            var previous = Console.Out;
            using var output = new StringWriter();
            try
            {
                Console.SetOut(output);
                foreach (string[] args in new[] { Array.Empty<string>(), new[] { "software", "extra" },
                    new[] { "tpm", "extra" }, new[] { "list", "extra" }, new[] { "get", "software", "../invalid" } })
                    assert(new TpmVaultApp().Run(args) == 1, "CLI rejects unsafe/malformed request before key access");
            }
            finally { Console.SetOut(previous); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(recovered);
            if (unwrapped is not null) CryptographicOperations.ZeroMemory(unwrapped);
        }
    }
}

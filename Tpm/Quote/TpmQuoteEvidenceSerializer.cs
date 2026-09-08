using System.Buffers.Binary;
using TPMVault.Configuration;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tpm2Lib;

namespace TPMVault.Tpm.Quote;

/// <summary>Exports verified public evidence and validates its portable JSON schema.</summary>
public sealed class TpmQuoteEvidenceSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false
    };

    public string ValidateOutputPath(string path) => ValidatePath(path, mustExist: false);

    public string ValidateInputPath(string path) => ValidatePath(path, mustExist: true);

    private static string ValidatePath(string path, bool mustExist)
    {
        string fullPath = RepositoryPaths.Resolve(path);
        RepositoryPaths.RejectLinks(fullPath);
        if (!Directory.Exists(Path.GetDirectoryName(fullPath)))
            throw new DirectoryNotFoundException("Evidence parent directory must already exist.");
        try
        {
            var attributes = File.GetAttributes(fullPath);
            if (!mustExist) throw new IOException("Output already exists; evidence files are never overwritten.");
            if ((attributes & FileAttributes.Directory) != 0)
                throw new ArgumentException("Evidence input must be a regular file.");
            return fullPath;
        }
        catch (FileNotFoundException)
        {
            if (mustExist) throw new FileNotFoundException("Evidence file does not exist.", fullPath);
            return fullPath;
        }
    }
    public string SerializeVerified(TpmQuoteEvidence evidence, byte[] expectedNonce)
    {
        var verification = TpmQuoteVerifier.Verify(evidence, expectedNonce);
        if (!verification.Verified)
            throw new InvalidOperationException("Evidence export refused: " + string.Join("; ",
                verification.Checks.Where(c => !c.Valid).Select(c => $"{c.Name}: {c.Error}")));

        var parameters = (RsaParms)evidence.PublicKey.parameters;
        var modulus = (Tpm2bPublicKeyRsa)evidence.PublicKey.unique;
        byte[] exponent = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(exponent, parameters.exponent == 0 ? 65537u : parameters.exponent);
        using RSA publicRsa = RSA.Create();
        // Import only n and e. No sensitive/private TPM structure is consulted.
        publicRsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus.buffer,
            Exponent = exponent.SkipWhile(b => b == 0).ToArray()
        });

        var file = new TpmQuoteEvidenceFile
        {
            Format = "TPMVault.TpmQuote",
            Version = 1,
            HashAlgorithm = "SHA-256",
            PcrIndexes = [0, 2, 4, 7],
            PcrValues = evidence.PcrValues.OrderBy(p => p.Key).ToDictionary(
                p => p.Key, p => Convert.ToBase64String(Convert.FromHexString(p.Value))),
            Nonce = Convert.ToBase64String(expectedNonce),
            AttestationFormat = "TPMS_ATTEST",
            Attestation = Convert.ToBase64String(evidence.Attestation.GetTpmRepresentation()),
            SignatureAlgorithm = "RSASSA-PKCS1-v1_5",
            Signature = Convert.ToBase64String(((SignatureRsassa)evidence.Signature).sig),
            PublicKeyFormat = "SubjectPublicKeyInfo-DER",
            PublicKey = Convert.ToBase64String(publicRsa.ExportSubjectPublicKeyInfo())
        };
        Validate(file);
        return JsonSerializer.Serialize(file, JsonOptions);
    }

    public string WriteVerified(TpmQuoteEvidence evidence, byte[] expectedNonce, string outputPath)
    {
        // Complete verification and serialization before creating any file.
        string json = SerializeVerified(evidence, expectedNonce);
        string path = ValidateOutputPath(outputPath);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        stream.Write(bytes);
        stream.Flush();
        return path;
    }

    /// <summary>Schema/encoding validation only. This does NOT verify a Quote.</summary>
    public TpmQuoteEvidenceFile Deserialize(string json)
    {
        var file = DeserializeSchema(json);
        Validate(file);
        return file;
    }

    internal static TpmQuoteEvidenceFile DeserializeSchema(string json) =>
        JsonSerializer.Deserialize<TpmQuoteEvidenceFile>(json, JsonOptions)
        ?? throw new InvalidDataException("Evidence JSON cannot be null.");

    private static void Validate(TpmQuoteEvidenceFile file)
    {
        if (file.Format != "TPMVault.TpmQuote" || file.Version != 1)
            throw new InvalidDataException("Unsupported evidence format/version.");
        if (file.HashAlgorithm != "SHA-256" || file.AttestationFormat != "TPMS_ATTEST" ||
            file.SignatureAlgorithm != "RSASSA-PKCS1-v1_5" || file.PublicKeyFormat != "SubjectPublicKeyInfo-DER")
            throw new InvalidDataException("Missing or unsupported algorithm/encoding field.");
        uint[] indexes = [0, 2, 4, 7];
        if (file.PcrIndexes is null || !file.PcrIndexes.SequenceEqual(indexes) ||
            file.PcrValues is null || !file.PcrValues.Keys.Order().SequenceEqual(indexes))
            throw new InvalidDataException("Evidence must contain SHA-256 PCRs 0, 2, 4, 7.");
        foreach (uint index in indexes) Decode(file.PcrValues[index], $"PCR {index}", 32);
        Decode(file.Nonce, "nonce", 32);
        Decode(file.Attestation, "attestation");
        Decode(file.Signature, "signature", 256);
        byte[] publicKey = Decode(file.PublicKey, "publicKey");
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKey, out int consumed);
        if (consumed != publicKey.Length || rsa.KeySize != 2048)
            throw new InvalidDataException("Expected one RSA-2048 SubjectPublicKeyInfo value.");
    }

    internal static byte[] Decode(string? value, string field, int? size = null)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException($"Missing {field}.");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(value); }
        catch (FormatException ex) { throw new InvalidDataException($"Malformed Base64 in {field}.", ex); }
        if (bytes.Length == 0 || (size.HasValue && bytes.Length != size))
            throw new InvalidDataException($"Invalid {field} length.");
        return bytes;
    }
}

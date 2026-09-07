using System;
using System.Security.Cryptography;

// Change this value to switch between software and TPM.
KeyBackend backend;

if (args.Length == 0)
{
    backend = KeyBackend.Tpm;
}
else if (args[0].Equals("software", StringComparison.OrdinalIgnoreCase))
{
    backend = KeyBackend.Software;
}
else if (args[0].Equals("tpm", StringComparison.OrdinalIgnoreCase))
{
    backend = KeyBackend.Tpm;
}
else
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  dotnet run -- software");
    Console.WriteLine("  dotnet run -- tpm");
    return;
}
// Use a different persistent key name for each backend.
string keyName = backend switch
{
    KeyBackend.Software => "TPMVault.SoftwareKey",
    KeyBackend.Tpm => "TPMVault.TpmKey",
    _ => throw new InvalidOperationException("Unsupported backend.")
};

// Select the Windows provider that will manage the key.
CngProvider provider = backend switch
{
    KeyBackend.Software => CngProvider.MicrosoftSoftwareKeyStorageProvider,
    KeyBackend.Tpm => CngProvider.MicrosoftPlatformCryptoProvider,
    _ => throw new InvalidOperationException("Unsupported backend.")
};

Console.WriteLine("TPMVault - Backend Comparison");
Console.WriteLine();
Console.WriteLine($"Selected backend: {backend}");
Console.WriteLine($"Provider:         {provider.Provider}");
Console.WriteLine();

try
{
    // Open the existing key or create it if it does not exist.
    using CngKey key = GetOrCreateKey(keyName, provider);

    PrintKeyInfo(key, backend);

    // Generate random data that we will sign.
    byte[] challenge = RandomNumberGenerator.GetBytes(32);

    // Use the CNG key through the RSA API.
    using var rsa = new RSACng(key);

    // Sign the challenge using the private key.
    byte[] signature = rsa.SignData(
        challenge,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    // Verify the signature using the public key.
    bool isValid = rsa.VerifyData(
        challenge,
        signature,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    Console.WriteLine();
    Console.WriteLine($"Challenge:        {Convert.ToHexString(challenge)}");
    Console.WriteLine($"Signature length: {signature.Length} bytes");
    Console.WriteLine($"Signature valid:  {isValid}");
}
catch (CryptographicException ex)
{
    Console.WriteLine();
    Console.WriteLine("Cryptographic operation failed:");
    Console.WriteLine(ex.Message);
}

static CngKey GetOrCreateKey(
    string keyName,
    CngProvider provider)
{
    // Reuse the same persistent key if it already exists.
    if (CngKey.Exists(keyName, provider))
    {
        return CngKey.Open(keyName, provider);
    }

    // Define how the RSA key should be created.
    var creationParameters = new CngKeyCreationParameters
    {
        Provider = provider,
        KeyUsage =
            CngKeyUsages.Signing |
            CngKeyUsages.Decryption
    };

    // Create a persistent RSA key under the selected provider.
    return CngKey.Create(
        CngAlgorithm.Rsa,
        keyName,
        creationParameters);
}

static void PrintKeyInfo(
    CngKey key,
    KeyBackend backend)
{
    Console.WriteLine("Key information");
    Console.WriteLine("------------------------");
    Console.WriteLine($"Backend:   {backend}");
    Console.WriteLine($"Name:      {key.KeyName}");
    Console.WriteLine($"Algorithm: {key.Algorithm}");
    Console.WriteLine($"Provider:  {key.Provider}");
}

// Defines which type of key storage we want to use.
enum KeyBackend
{
    Software,
    Tpm
}
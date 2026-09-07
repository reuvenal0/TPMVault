using System;
using System.Security.Cryptography;

const string keyName = "TPMVault.TestKey";

CngProvider provider =
    CngProvider.MicrosoftPlatformCryptoProvider;

Console.WriteLine("TPMVault - TPM Key Test");
Console.WriteLine();

try
{
    if (CngKey.Exists(keyName, provider))
    {
        Console.WriteLine("Existing TPM key found.");

        using CngKey key =
            CngKey.Open(keyName, provider);

        PrintKeyInfo(key);
    }
    else
    {
        Console.WriteLine("No existing key found.");
        Console.WriteLine("Creating TPM-backed key...");

        var creationParameters = new CngKeyCreationParameters
        {
            Provider = provider,

            KeyUsage =
                CngKeyUsages.Signing |
                CngKeyUsages.Decryption
        };

        using CngKey key = CngKey.Create(
            CngAlgorithm.Rsa,
            keyName,
            creationParameters);

        Console.WriteLine("Key created successfully.");

        PrintKeyInfo(key);
    }
}
catch (CryptographicException ex)
{
    Console.WriteLine("Cryptographic operation failed:");
    Console.WriteLine(ex.Message);
}

static void PrintKeyInfo(CngKey key)
{
    Console.WriteLine();
    Console.WriteLine("Key information");
    Console.WriteLine("------------------------");
    Console.WriteLine($"Name:      {key.KeyName}");
    Console.WriteLine($"Algorithm: {key.Algorithm}");
    Console.WriteLine($"Provider:  {key.Provider}");
}
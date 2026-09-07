using System;
using System.Security.Cryptography;

const string keyName = "TPMVault.TestKey";

Console.WriteLine("TPMVault - TPM Key Test");
Console.WriteLine();

try
{
    var creationParameters = new CngKeyCreationParameters
    {
        Provider = CngProvider.MicrosoftPlatformCryptoProvider,

        KeyUsage =
            CngKeyUsages.Signing |
            CngKeyUsages.Decryption
    };

    using CngKey key = CngKey.Create(
        CngAlgorithm.Rsa,
        keyName,
        creationParameters);

    Console.WriteLine("TPM-backed key created successfully.");
    Console.WriteLine();

    Console.WriteLine($"Key name:  {key.KeyName}");
    Console.WriteLine($"Algorithm: {key.Algorithm}");
    Console.WriteLine($"Provider:  {key.Provider}");
}
catch (CryptographicException ex)
{
    Console.WriteLine("Failed to create TPM-backed key.");
    Console.WriteLine();
    Console.WriteLine(ex.Message);
}
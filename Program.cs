using System;
using System.Security.Cryptography;

// This is the persistent name of the cryptographic key.
//
// Because the key has a name, Windows can store it persistently.
// That means the key can still exist after the program exits,
// and we can open the same key again in a later execution.
const string keyName = "TPMVault.TestKey";


// Select the Windows cryptographic provider that uses the TPM.
//
// MicrosoftPlatformCryptoProvider tells Windows that we want
// the key to be created and managed through the platform TPM provider,
// rather than by the regular software-based key storage provider.
CngProvider provider =
    CngProvider.MicrosoftPlatformCryptoProvider;


// Print a small title so the console output is easier to understand.
Console.WriteLine("TPMVault - TPM Signing Test");
Console.WriteLine();

try
{
    // Get the TPM-backed key that we will use for signing.
    //
    // If the key already exists from a previous execution,
    // the method will open the existing key.
    //
    // If the key does not exist yet,
    // the method will create a new persistent RSA key.
    //
    // "using" ensures that the CngKey handle is released correctly
    // when we finish using it.
    using CngKey key = GetOrCreateKey(keyName, provider);


    // Print useful information about the key so we can verify
    // which algorithm and provider are actually being used.
    PrintKeyInfo(key);


    Console.WriteLine();
    Console.WriteLine("Generating random challenge...");


    // Generate 32 cryptographically secure random bytes.
    //
    // 32 bytes = 256 bits.
    //
    // This random value acts as a "challenge":
    // some unpredictable data that we will sign with the private key.
    //
    // RandomNumberGenerator uses a cryptographically secure
    // source of randomness provided by the operating system.
    byte[] challenge = RandomNumberGenerator.GetBytes(32);


    // Convert the random bytes to hexadecimal form only for display.
    //
    // The actual challenge remains the original byte[].
    Console.WriteLine(
        $"Challenge: {Convert.ToHexString(challenge)}");


    // Create an RSA object that uses the CngKey we already opened.
    //
    // This is important:
    // RSACng is not creating a new key here.
    //
    // It is wrapping the existing TPM-backed CngKey
    // so we can use the standard RSA signing and verification API.
    using var rsa = new RSACng(key);


    // Sign the random challenge.
    //
    // Internally, SignData first hashes the challenge using SHA-256.
    //
    // Conceptually:
    //
    // challenge
    //    |
    //    v
    // SHA-256
    //    |
    //    v
    // hash
    //    |
    //    v
    // RSA private-key operation
    //    |
    //    v
    // signature
    //
    // Because the RSA private key is TPM-backed,
    // the private-key signing operation is performed through
    // the TPM-backed Windows cryptographic provider.
    //
    // PKCS#1 v1.5 is used here as the RSA signature padding scheme.
    byte[] signature = rsa.SignData(
        challenge,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);


    Console.WriteLine();
    Console.WriteLine("Challenge signed successfully.");


    // Print the signature size.
    //
    // For an RSA key, the signature length normally matches
    // the RSA modulus size.
    //
    // For example:
    // RSA-2048 normally produces a 256-byte signature.
    Console.WriteLine(
        $"Signature length: {signature.Length} bytes");


    // Verify that the generated signature really matches
    // the original challenge.
    //
    // Verification uses the RSA public key.
    //
    // If:
    // 1. the challenge is unchanged,
    // 2. the signature is unchanged,
    // 3. the correct public key is used,
    //
    // then VerifyData should return true.
    //
    // If even one byte of the challenge or signature changes,
    // verification should fail.
    bool isValid = rsa.VerifyData(
        challenge,
        signature,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);


    Console.WriteLine();

    Console.WriteLine(
        $"Signature valid: {isValid}");
}
catch (CryptographicException ex)
{
    // CryptographicException is commonly thrown when something
    // related to Windows CNG, the provider, the key, or the TPM fails.
    //
    // Examples could include:
    // - TPM is unavailable
    // - the provider cannot be opened
    // - the key cannot be created
    // - the key does not support the requested operation
    Console.WriteLine();
    Console.WriteLine("Cryptographic operation failed:");
    Console.WriteLine(ex.Message);
}


// Return an existing persistent key,
// or create a new one if it does not exist yet.
static CngKey GetOrCreateKey(
    string keyName,
    CngProvider provider)
{
    // Check whether Windows already has a persistent key
    // with this name under the selected provider.
    if (CngKey.Exists(keyName, provider))
    {
        Console.WriteLine("Opening existing TPM-backed key.");


        // Open the existing persistent key.
        //
        // No new key is created here.
        //
        // This demonstrates that the key survives
        // after the application exits.
        return CngKey.Open(
            keyName,
            provider);
    }


    Console.WriteLine("Creating new TPM-backed key.");


    // Define how the new key should be created.
    var creationParameters =
        new CngKeyCreationParameters
        {
            // Store and manage the key using the provider
            // that was passed to this method.
            //
            // In our current program this is:
            // Microsoft Platform Crypto Provider.
            Provider = provider,


            // Define which private-key operations
            // this key is allowed to perform.
            //
            // Signing:
            // allows the private key to create RSA signatures.
            //
            // Decryption:
            // allows the private key to decrypt data.
            //
            // We will need decryption later when the TPM-backed
            // RSA key protects the AES key used by TPMVault.
            KeyUsage =
                CngKeyUsages.Signing |
                CngKeyUsages.Decryption
        };


    // Create a new persistent RSA key.
    //
    // Parameters:
    //
    // CngAlgorithm.Rsa
    //     -> create an RSA key
    //
    // keyName
    //     -> assign a persistent name to the key
    //
    // creationParameters
    //     -> use the provider and permissions defined above
    //
    // Because the provider is the Microsoft Platform Crypto Provider,
    // this becomes a TPM-backed RSA key.
    return CngKey.Create(
        CngAlgorithm.Rsa,
        keyName,
        creationParameters);
}


// Print information about the key currently being used.
static void PrintKeyInfo(CngKey key)
{
    Console.WriteLine();
    Console.WriteLine("Key information");
    Console.WriteLine("------------------------");


    // Persistent name assigned to the key.
    Console.WriteLine($"Name:      {key.KeyName}");


    // Cryptographic algorithm used by the key.
    //
    // In this project we expect RSA.
    Console.WriteLine($"Algorithm: {key.Algorithm}");


    // The Windows Key Storage Provider that manages the key.
    //
    // For our TPM-backed key we expect:
    //
    // Microsoft Platform Crypto Provider
    Console.WriteLine($"Provider:  {key.Provider}");
}
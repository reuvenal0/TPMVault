using System.Security.Cryptography;
using System.Text;

namespace TPMVault;

/// <summary>
/// Runs the cryptographic demonstrations for the selected key backend.
/// </summary>
public sealed class CryptoDemoService
{
    public void Run(CngKey key)
    {
        using var rsa = new RSACng(key);

        RunPrivateKeyExportTest(rsa);
        RunSignatureTest(rsa);
        RunAesGcmTest();
    }

    private static void RunPrivateKeyExportTest(RSA rsa)
    {
        Console.WriteLine();
        Console.WriteLine("Trying to export private key...");

        byte[]? privateKey = null;

        try
        {
            privateKey = rsa.ExportPkcs8PrivateKey();

            Console.WriteLine(
                $"Private key export succeeded: {privateKey.Length} bytes");
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine("Private key export failed.");
            Console.WriteLine($"Reason: {ex.Message}");
        }
        finally
        {
            // Clear exported private key material as soon as possible.
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    private static void RunSignatureTest(RSA rsa)
    {
        // Generate a random 256-bit challenge.
        byte[] challenge = RandomNumberGenerator.GetBytes(32);

        // Sign the challenge with the private key.
        byte[] signature = rsa.SignData(
            challenge,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Verify the signature with the corresponding public key.
        bool isValid = rsa.VerifyData(
            challenge,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        Console.WriteLine();
        Console.WriteLine(
            $"Challenge:        {Convert.ToHexString(challenge)}");
        Console.WriteLine(
            $"Signature length: {signature.Length} bytes");
        Console.WriteLine(
            $"Signature valid:  {isValid}");
    }

    private static void RunAesGcmTest()
    {
        Console.WriteLine();
        Console.WriteLine("AES-GCM encryption test");
        Console.WriteLine("------------------------");

        const string secret = "My very secret value";

        byte[] plaintext = Encoding.UTF8.GetBytes(secret);

        // Generate a random 256-bit AES key.
        byte[] aesKey = RandomNumberGenerator.GetBytes(32);

        // AES-GCM commonly uses a 96-bit nonce.
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        byte[] ciphertext = new byte[plaintext.Length];

        // Use a 128-bit authentication tag.
        byte[] tag = new byte[16];

        byte[] decrypted = new byte[ciphertext.Length];

        try
        {
            using (var aes = new AesGcm(aesKey, tag.Length))
            {
                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext,
                    tag);
            }

            Console.WriteLine($"Original secret:  {secret}");
            Console.WriteLine(
                $"Ciphertext:       {Convert.ToHexString(ciphertext)}");
            Console.WriteLine(
                $"Nonce:            {Convert.ToHexString(nonce)}");
            Console.WriteLine(
                $"Tag:              {Convert.ToHexString(tag)}");

            using (var aes = new AesGcm(aesKey, tag.Length))
            {
                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    decrypted);
            }

            string decryptedSecret =
                Encoding.UTF8.GetString(decrypted);

            Console.WriteLine(
                $"Decrypted secret: {decryptedSecret}");
        }
        finally
        {
            // Clear temporary sensitive data after the demonstration.
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }
}

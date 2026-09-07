using System.Security.Cryptography;
using System.Text;

namespace TPMVault;

/// <summary>
/// Runs small cryptographic demonstrations for the selected backend.
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
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    private static void RunSignatureTest(RSA rsa)
    {
        byte[] challenge =
            RandomNumberGenerator.GetBytes(32);

        byte[] signature = rsa.SignData(
            challenge,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

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

        byte[] plaintext =
            Encoding.UTF8.GetBytes(secret);

        byte[] aesKey =
            RandomNumberGenerator.GetBytes(32);

        byte[] nonce =
            RandomNumberGenerator.GetBytes(12);

        byte[] ciphertext =
            new byte[plaintext.Length];

        byte[] tag =
            new byte[16];

        byte[] decrypted =
            new byte[ciphertext.Length];

        try
        {
            using (var aes =
                new AesGcm(aesKey, tag.Length))
            {
                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext,
                    tag);
            }

            Console.WriteLine(
                $"Original secret:  {secret}");
            Console.WriteLine(
                $"Ciphertext:       {Convert.ToHexString(ciphertext)}");
            Console.WriteLine(
                $"Nonce:            {Convert.ToHexString(nonce)}");
            Console.WriteLine(
                $"Tag:              {Convert.ToHexString(tag)}");

            using (var aes =
                new AesGcm(aesKey, tag.Length))
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
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }
}

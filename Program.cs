using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// Choose which key backend to use.
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

// Handle the "list" command before choosing a backend.
else if (args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
{
    ListAllKeys();
    return;
}

// Handle the "delete" command.
else if (args.Length == 3 &&
    args[0].Equals("delete", StringComparison.OrdinalIgnoreCase))
{
    DeleteKey(args[1], args[2]);
    return;
}

else
{
    PrintUsage();
    return;
}

// Use a different persistent key name for each backend.
string keyName = backend switch
{
    KeyBackend.Software => "TPMVault.SoftwareKeyV2",
    KeyBackend.Tpm => "TPMVault.TpmKeyV2",
    _ => throw new InvalidOperationException("Unsupported backend.")
};

// Select the Windows provider that manages the key.
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
    // Open the existing key or create it if needed.
    using CngKey key = GetOrCreateKey(keyName, provider);

    PrintKeyInfo(key, backend);

    // Generate random data to sign.
    byte[] challenge = RandomNumberGenerator.GetBytes(32);

    // Use the CNG key through the RSA API.
    using var rsa = new RSACng(key);

    Console.WriteLine();
    Console.WriteLine("Trying to export private key...");

    try
    {
        byte[] privateKey = rsa.ExportPkcs8PrivateKey();

        Console.WriteLine(
            $"Private key export succeeded: {privateKey.Length} bytes");

        // Clear exported private key material from managed memory.
        CryptographicOperations.ZeroMemory(privateKey);
    }
    catch (CryptographicException ex)
    {
        Console.WriteLine("Private key export failed.");
        Console.WriteLine($"Reason: {ex.Message}");
    }

    // Sign using the private key.
    byte[] signature = rsa.SignData(
        challenge,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    // Verify using the corresponding public key.
    bool isValid = rsa.VerifyData(
        challenge,
        signature,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    Console.WriteLine();
    Console.WriteLine($"Challenge:        {Convert.ToHexString(challenge)}");
    Console.WriteLine($"Signature length: {signature.Length} bytes");
    Console.WriteLine($"Signature valid:  {isValid}");

    Console.WriteLine();
    Console.WriteLine("AES-GCM encryption test");
    Console.WriteLine("------------------------");

    string secret = "My very secret value";

    byte[] plaintext =
        System.Text.Encoding.UTF8.GetBytes(secret);

    // Generate a random AES-256 key.
    byte[] aesKey = RandomNumberGenerator.GetBytes(32);

    // AES-GCM normally uses a 12-byte nonce.
    byte[] nonce = RandomNumberGenerator.GetBytes(12);

    byte[] ciphertext = new byte[plaintext.Length];

    // Use a 128-bit authentication tag.
    byte[] tag = new byte[16];

    using (var aes = new AesGcm(aesKey, 16))
    {
        aes.Encrypt(
            nonce,
            plaintext,
            ciphertext,
            tag);
    }

    Console.WriteLine($"Original secret:  {secret}");
    Console.WriteLine($"Ciphertext:       {Convert.ToHexString(ciphertext)}");
    Console.WriteLine($"Nonce:            {Convert.ToHexString(nonce)}");
    Console.WriteLine($"Tag:              {Convert.ToHexString(tag)}");

    byte[] decrypted = new byte[ciphertext.Length];

    using (var aes = new AesGcm(aesKey, 16))
    {
        aes.Decrypt(
            nonce,
            ciphertext,
            tag,
            decrypted);
    }

    string decryptedSecret =
        System.Text.Encoding.UTF8.GetString(decrypted);

    Console.WriteLine($"Decrypted secret: {decryptedSecret}");

    // Clear sensitive key material after use.
    CryptographicOperations.ZeroMemory(aesKey);
    CryptographicOperations.ZeroMemory(plaintext);
    CryptographicOperations.ZeroMemory(decrypted);
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
    if (CngKey.Exists(keyName, provider))
    {
        return CngKey.Open(keyName, provider);
    }

    var creationParameters = new CngKeyCreationParameters
    {
        Provider = provider,
        KeyUsage =
            CngKeyUsages.Signing |
            CngKeyUsages.Decryption
    };

    // Use RSA-2048 for both backends.
    creationParameters.Parameters.Add(
        new CngProperty(
            "Length",
            BitConverter.GetBytes(2048),
            CngPropertyOptions.Persist));

    // Only the software key is intentionally exportable.
    if (provider == CngProvider.MicrosoftSoftwareKeyStorageProvider)
    {
        creationParameters.ExportPolicy =
            CngExportPolicies.AllowExport |
            CngExportPolicies.AllowPlaintextExport;
    }

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

static void ListAllKeys()
{
    Console.WriteLine("TPMVault - Stored Keys");
    Console.WriteLine();

    ListKeysForProvider(
        "Software keys",
        CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider);

    Console.WriteLine();

    ListKeysForProvider(
        "TPM keys",
        CngProvider.MicrosoftPlatformCryptoProvider.Provider);
}

static void ListKeysForProvider(
    string title,
    string providerName)
{
    Console.WriteLine(title);
    Console.WriteLine(new string('-', title.Length));
    Console.WriteLine($"Provider: {providerName}");
    Console.WriteLine();

    IntPtr providerHandle = IntPtr.Zero;
    IntPtr enumState = IntPtr.Zero;

    int status = NativeMethods.NCryptOpenStorageProvider(
        out providerHandle,
        providerName,
        0);

    if (status != 0)
    {
        Console.WriteLine(
            $"Could not open provider. Error: 0x{status:X8}");
        return;
    }

    int count = 0;

    try
    {
        while (true)
        {
            IntPtr keyNamePointer = IntPtr.Zero;

            status = NativeMethods.NCryptEnumKeys(
                providerHandle,
                null,
                out keyNamePointer,
                ref enumState,
                0);

            if (status == NativeMethods.NteNoMoreItems)
            {
                break;
            }

            if (status != 0)
            {
                Console.WriteLine(
                    $"Enumeration failed. Error: 0x{status:X8}");
                break;
            }

            try
            {
                NativeMethods.NCryptKeyName keyInfo =
                    Marshal.PtrToStructure<NativeMethods.NCryptKeyName>(
                        keyNamePointer);

                string? name =
                    Marshal.PtrToStringUni(keyInfo.Name);

                string? algorithm =
                    Marshal.PtrToStringUni(keyInfo.Algorithm);

                Console.WriteLine(
                    $"{name}  [{algorithm}]");

                count++;
            }
            finally
            {
                if (keyNamePointer != IntPtr.Zero)
                {
                    NativeMethods.NCryptFreeBuffer(
                        keyNamePointer);
                }
            }
        }

        if (count == 0)
        {
            Console.WriteLine("No keys found.");
        }
    }
    finally
    {
        if (enumState != IntPtr.Zero)
        {
            NativeMethods.NCryptFreeBuffer(enumState);
        }

        if (providerHandle != IntPtr.Zero)
        {
            NativeMethods.NCryptFreeObject(providerHandle);
        }
    }
}

static void PrintUsage()
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  dotnet run -- software");
    Console.WriteLine("  dotnet run -- tpm");
    Console.WriteLine("  dotnet run -- list");
    Console.WriteLine("  dotnet run -- delete <software|tpm> <key-name>");
}


static void DeleteKey(
    string backendName,
    string keyName)
{
    CngProvider provider = backendName.ToLowerInvariant() switch
    {
        "software" => CngProvider.MicrosoftSoftwareKeyStorageProvider,
        "tpm" => CngProvider.MicrosoftPlatformCryptoProvider,
        _ => throw new ArgumentException(
            "Backend must be 'software' or 'tpm'.")
    };

    if (!CngKey.Exists(keyName, provider))
    {
        Console.WriteLine($"Key not found: {keyName}");
        return;
    }

    using CngKey key = CngKey.Open(
        keyName,
        provider);

    key.Delete();

    Console.WriteLine($"Deleted key: {keyName}");
}

// Defines which key storage backend to use.
enum KeyBackend
{
    Software,
    Tpm
}

// Native Windows CNG functions used to enumerate keys.
static class NativeMethods
{
    public const int NteNoMoreItems =
        unchecked((int)0x8009002A);

    [StructLayout(LayoutKind.Sequential)]
    public struct NCryptKeyName
    {
        public IntPtr Name;
        public IntPtr Algorithm;
        public uint LegacyKeySpec;
        public uint Flags;
    }

    [DllImport(
        "ncrypt.dll",
        CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(
        out IntPtr providerHandle,
        string providerName,
        uint flags);

    [DllImport(
        "ncrypt.dll",
        CharSet = CharSet.Unicode)]
    public static extern int NCryptEnumKeys(
        IntPtr providerHandle,
        string? scope,
        out IntPtr keyName,
        ref IntPtr enumState,
        uint flags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeBuffer(
        IntPtr buffer);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(
        IntPtr handle);
}
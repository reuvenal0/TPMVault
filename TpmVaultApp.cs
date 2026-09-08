using System.Security.Cryptography;

namespace TPMVault;

/// <summary>
/// Handles command-line routing and coordinates the application services.
/// </summary>
public sealed class TpmVaultApp
{
    private readonly KeyManager _keyManager;
    private readonly CryptoDemoService _cryptoDemoService;
    private readonly KeyEnumerator _keyEnumerator;
    private readonly VaultService _vaultService;
    private readonly AttestationKeyManager _attestationKeyManager;
    private readonly AttestationService _attestationService;

    public TpmVaultApp()
    {
        _keyManager = new KeyManager();
        _cryptoDemoService = new CryptoDemoService();
        _keyEnumerator = new KeyEnumerator();
        _vaultService = new VaultService();
        _attestationKeyManager = new AttestationKeyManager();
        _attestationService = new AttestationService();
    }

    public int Run(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                RunBackend(KeyBackend.Tpm);
                return 0;
            }

            string command =
                args[0].ToLowerInvariant();

            return command switch
            {
                "software" => RunBackendCommand(KeyBackend.Software),
                "tpm" => RunBackendCommand(KeyBackend.Tpm),
                "list" => ListKeysCommand(),
                "delete" => HandleDeleteKeyCommand(args),
                "put" => HandlePutCommand(args),
                "get" => HandleGetCommand(args),
                "list-secrets" => HandleListSecretsCommand(args),
                "inspect" => HandleInspectCommand(args),
                "delete-secret" => HandleDeleteSecretCommand(args),
                "attest" => HandleAttestCommand(args),
                "tpm-info" => HandleTpmReadCommand(args, readPcrs: false),
                "pcrs" => HandleTpmReadCommand(args, readPcrs: true),
                "quote" => HandleQuoteCommand(args),
                _ => PrintUsageAndFail()
            };
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine();
            Console.WriteLine("Cryptographic operation failed:");
            Console.WriteLine(ex.Message);
            return 1;
        }
        catch (Exception ex)
            when (ex is ArgumentException
                or InvalidOperationException
                or IOException
                or UnauthorizedAccessException
                or FormatException)
        {
            Console.WriteLine(ex.Message);
            return 1;
        }
    }

    private int RunBackendCommand(
        KeyBackend backend)
    {
        RunBackend(backend);
        return 0;
    }

    private int ListKeysCommand()
    {
        ListAllKeys();
        return 0;
    }

    private void RunBackend(
        KeyBackend backend)
    {
        KeyConfiguration configuration =
            _keyManager.GetConfiguration(backend);

        Console.WriteLine("TPMVault - Backend Comparison");
        Console.WriteLine();
        Console.WriteLine(
            $"Selected backend: {configuration.Backend}");
        Console.WriteLine(
            $"Provider:         {configuration.Provider.Provider}");
        Console.WriteLine();

        using CngKey key =
            _keyManager.GetOrCreateKey(backend);

        PrintKeyInfo(
            key,
            configuration);

        _cryptoDemoService.Run(key);
    }

    private int HandlePutCommand(
        string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 1;
        }

        if (!TryParseBackend(
            args[1],
            out KeyBackend backend))
        {
            return PrintInvalidBackend();
        }

        string name =
            args[2];

        Console.Write("Enter secret: ");

        string? secret =
            Console.ReadLine();

        if (string.IsNullOrEmpty(secret))
        {
            Console.WriteLine(
                "Secret cannot be empty.");
            return 1;
        }

        using CngKey key =
            _keyManager.GetOrCreateKey(backend);

        _vaultService.StoreSecret(
            name,
            secret,
            key,
            backend);

        Console.WriteLine(
            $"Secret stored: vault\\{backend.ToString().ToLowerInvariant()}\\{name}.vault");

        return 0;
    }

    private int HandleGetCommand(
        string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 1;
        }

        if (!TryParseBackend(
            args[1],
            out KeyBackend backend))
        {
            return PrintInvalidBackend();
        }

        string name =
            args[2];

        using CngKey key =
            _keyManager.GetOrCreateKey(backend);

        string secret =
            _vaultService.LoadSecret(
                name,
                key,
                backend);

        Console.WriteLine(
            $"Secret: {secret}");

        return 0;
    }

    private int HandleListSecretsCommand(
        string[] args)
    {
        if (args.Length != 2)
        {
            PrintUsage();
            return 1;
        }

        if (!TryParseBackend(
            args[1],
            out KeyBackend backend))
        {
            return PrintInvalidBackend();
        }

        IReadOnlyList<string> secrets =
            _vaultService.ListSecrets(backend);

        Console.WriteLine(
            $"Vault secrets ({backend})");

        Console.WriteLine(
            "------------------------");

        if (secrets.Count == 0)
        {
            Console.WriteLine(
                "No secrets found.");
            return 0;
        }

        foreach (string secretName in secrets)
        {
            Console.WriteLine(secretName);
        }

        return 0;
    }

    private int HandleInspectCommand(
        string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 1;
        }

        if (!TryParseBackend(
            args[1],
            out KeyBackend backend))
        {
            return PrintInvalidBackend();
        }

        VaultEntryMetadata metadata =
            _vaultService.Inspect(
                backend,
                args[2]);

        Console.WriteLine("Vault entry");
        Console.WriteLine("------------------------");
        Console.WriteLine(
            $"Name:           {metadata.Name}");
        Console.WriteLine(
            $"Backend:        {metadata.Backend}");
        Console.WriteLine(
            $"Version:        {metadata.Version}");
        Console.WriteLine(
            $"Ciphertext:     {metadata.CiphertextBytes} bytes");
        Console.WriteLine(
            $"Wrapped key:    {metadata.WrappedKeyBytes} bytes");
        Console.WriteLine(
            $"Nonce:          {metadata.NonceBytes} bytes");
        Console.WriteLine(
            $"Auth tag:       {metadata.TagBytes} bytes");

        return 0;
    }

    private int HandleDeleteSecretCommand(
        string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 1;
        }

        if (!TryParseBackend(
            args[1],
            out KeyBackend backend))
        {
            return PrintInvalidBackend();
        }

        string name =
            args[2];

        bool deleted =
            _vaultService.DeleteSecret(
                backend,
                name);

        if (!deleted)
        {
            Console.WriteLine(
                $"Secret not found: {name}");
            return 1;
        }

        Console.WriteLine(
            $"Deleted secret: {name}");

        return 0;
    }

    private static int HandleTpmReadCommand(string[] args, bool readPcrs)
    {
        if (args.Length != 1)
        {
            return PrintUsageAndFail();
        }

        try
        {
            using var device = new TpmDeviceService();
            if (readPcrs)
            {
                var pcrs = device.ReadSha256Pcrs();
                Console.WriteLine("TPMVault - PCR Values");
                Console.WriteLine("---------------------");
                Console.WriteLine();
                Console.WriteLine("Bank: SHA-256");
                Console.WriteLine();
                foreach (var pcr in pcrs)
                {
                    Console.WriteLine($"PCR {pcr.Key}: {pcr.Value}");
                }
            }
            else
            {
                TpmInformation info = device.GetInformation();
                Console.WriteLine("TPMVault - TPM Information");
                Console.WriteLine("--------------------------");
                Console.WriteLine("Connection:      OK");
                Console.WriteLine("Interface:       Windows TBS");
                Console.WriteLine("TPM 2.0 access:  Available");
                Console.WriteLine($"Manufacturer:    0x{info.Manufacturer:X8}");
                Console.WriteLine($"Firmware:        0x{info.FirmwareVersion1:X8} 0x{info.FirmwareVersion2:X8} (vendor-specific words)");
            }
            return 0;
        }
        // TSS.Net's TBS transport can throw plain Exception for context errors.
        // Keep this boundary local to the new commands, preserving existing handlers.
        catch (Exception ex)
        {
            Console.WriteLine("TPM 2.0 read through Windows TBS failed.");
            Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static int HandleQuoteCommand(string[] args)
    {
        if (args.Length != 1) return PrintUsageAndFail();
        Console.WriteLine("TPMVault - TPM Quote");
        Console.WriteLine("--------------------");
        try
        {
            TpmQuoteEvidence evidence = new TpmQuoteService().CreateQuote();
            TpmQuoteVerificationResult result = TpmQuoteVerifier.Verify(evidence, evidence.Nonce);
            Console.WriteLine("Connection:      OK");
            Console.WriteLine("PCR bank:        SHA-256");
            Console.WriteLine("PCRs:            0, 2, 4, 7");
            Console.WriteLine($"Nonce:           {Convert.ToHexString(evidence.Nonce)}");
            Console.WriteLine("Quote created:   Yes");
            Console.WriteLine("Transient key:   Flushed");
            Console.WriteLine("\nVerification\n------------");
            foreach (TpmQuoteCheck check in result.Checks)
            {
                Console.WriteLine($"{check.Name + ":",-18}{(check.Valid ? "Valid" : "FAILED")}");
                if (check.Error is not null) Console.WriteLine($"  {check.Error}");
            }
            Console.WriteLine(result.Verified
                ? "\nTPM quote:        VERIFIED\nLocal TPM Quote verified"
                : "\nQuote created but verification failed");
            return result.Verified ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex is TpmQuoteException { QuoteCreated: true }
                ? "Quote created but verification failed (evidence collection or cleanup failed)."
                : "Quote creation failed (evidence collection or cleanup may have failed).");
            Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private int HandleAttestCommand(
        string[] args)
    {
        if (args.Length != 1)
        {
            PrintUsage();
            return 1;
        }

        using CngKey attestationKey =
            _attestationKeyManager
                .GetOrCreateKey();

        Console.WriteLine(
            "TPMVault - TPM Attestation");

        Console.WriteLine(
            "------------------------");

        Console.WriteLine(
            $"Key:      {AttestationKeyManager.AttestationKeyName}");

        Console.WriteLine(
            $"Provider: {attestationKey.Provider}");

        AttestationResult result =
            _attestationService
                .CreatePlatformClaim(
                    attestationKey);

        if (!result.Success)
        {
            Console.WriteLine();
            Console.WriteLine(
                "Attestation claim creation failed.");

            Console.WriteLine(
                $"Native status: 0x{result.Status:X8}");

            Console.WriteLine(
                "The TPM identity key was created, but Windows rejected the platform claim request.");

            return 1;
        }

        byte[] claim =
            result.Claim!;

        byte[] nonce =
            result.Nonce!;

        try
        {
            byte[] claimHash =
                SHA256.HashData(
                    claim);

            Console.WriteLine();
            Console.WriteLine(
                "Platform claim created successfully.");

            Console.WriteLine(
                $"Claim size: {claim.Length} bytes");

            Console.WriteLine(
                $"Nonce:      {Convert.ToHexString(nonce)}");

            Console.WriteLine(
                $"SHA-256:    {Convert.ToHexString(claimHash)}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                claim);

            CryptographicOperations.ZeroMemory(
                nonce);
        }

        return 0;
    }

    private void ListAllKeys()
    {
        Console.WriteLine(
            "TPMVault - Stored Keys");
        Console.WriteLine();

        ListKeysForBackend(
            "Software keys",
            KeyBackend.Software);

        Console.WriteLine();

        ListKeysForBackend(
            "TPM keys",
            KeyBackend.Tpm);
    }

    private void ListKeysForBackend(
        string title,
        KeyBackend backend)
    {
        KeyConfiguration configuration =
            _keyManager.GetConfiguration(backend);

        IReadOnlyList<StoredKeyInfo> keys =
            _keyEnumerator.Enumerate(
                configuration.Provider);

        Console.WriteLine(title);
        Console.WriteLine(
            new string('-', title.Length));
        Console.WriteLine(
            $"Provider: {configuration.Provider.Provider}");
        Console.WriteLine();

        if (keys.Count == 0)
        {
            Console.WriteLine(
                "No keys found.");
            return;
        }

        foreach (StoredKeyInfo key in keys)
        {
            Console.WriteLine(
                $"{key.Name}  [{key.Algorithm}]");
        }
    }

    private int HandleDeleteKeyCommand(
        string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 1;
        }

        if (!TryParseBackend(
            args[1],
            out KeyBackend backend))
        {
            return PrintInvalidBackend();
        }

        string keyName =
            args[2];

        bool deleted =
            _keyManager.DeleteKey(
                backend,
                keyName);

        if (!deleted)
        {
            Console.WriteLine(
                $"Key not found: {keyName}");
            return 1;
        }

        Console.WriteLine(
            $"Deleted key: {keyName}");

        return 0;
    }

    private static bool TryParseBackend(
        string value,
        out KeyBackend backend)
    {
        if (value.Equals(
            "software",
            StringComparison.OrdinalIgnoreCase))
        {
            backend =
                KeyBackend.Software;
            return true;
        }

        if (value.Equals(
            "tpm",
            StringComparison.OrdinalIgnoreCase))
        {
            backend =
                KeyBackend.Tpm;
            return true;
        }

        backend = default;
        return false;
    }

    private static int PrintInvalidBackend()
    {
        Console.WriteLine(
            "Backend must be 'software' or 'tpm'.");
        return 1;
    }

    private static void PrintKeyInfo(
        CngKey key,
        KeyConfiguration configuration)
    {
        Console.WriteLine(
            "Key information");
        Console.WriteLine(
            "------------------------");
        Console.WriteLine(
            $"Backend:   {configuration.Backend}");
        Console.WriteLine(
            $"Name:      {key.KeyName}");
        Console.WriteLine(
            $"Algorithm: {key.Algorithm}");
        Console.WriteLine(
            $"Provider:  {key.Provider}");
    }

    private static int PrintUsageAndFail()
    {
        PrintUsage();
        return 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine(
            "  dotnet run -- software");
        Console.WriteLine(
            "  dotnet run -- tpm");
        Console.WriteLine(
            "  dotnet run -- list");
        Console.WriteLine(
            "  dotnet run -- delete <software|tpm> <key-name>");
        Console.WriteLine(
            "  dotnet run -- put <software|tpm> <secret-name>");
        Console.WriteLine(
            "  dotnet run -- get <software|tpm> <secret-name>");
        Console.WriteLine(
            "  dotnet run -- list-secrets <software|tpm>");
        Console.WriteLine(
            "  dotnet run -- inspect <software|tpm> <secret-name>");
        Console.WriteLine(
            "  dotnet run -- delete-secret <software|tpm> <secret-name>");
        Console.WriteLine(
            "  dotnet run -- attest");
        Console.WriteLine("  dotnet run -- tpm-info");
        Console.WriteLine("  dotnet run -- pcrs");
        Console.WriteLine("  dotnet run -- quote");
    }
}

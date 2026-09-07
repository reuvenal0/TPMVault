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

    public TpmVaultApp()
    {
        _keyManager = new KeyManager();
        _cryptoDemoService = new CryptoDemoService();
        _keyEnumerator = new KeyEnumerator();
        _vaultService = new VaultService();
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
    }
}

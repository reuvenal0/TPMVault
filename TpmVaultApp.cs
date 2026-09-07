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

    public TpmVaultApp()
    {
        _keyManager = new KeyManager();
        _cryptoDemoService = new CryptoDemoService();
        _keyEnumerator = new KeyEnumerator();
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

            string command = args[0].ToLowerInvariant();

            switch (command)
            {
                case "software":
                    RunBackend(KeyBackend.Software);
                    return 0;

                case "tpm":
                    RunBackend(KeyBackend.Tpm);
                    return 0;

                case "list":
                    ListAllKeys();
                    return 0;

                case "delete":
                    return HandleDeleteCommand(args);

                default:
                    PrintUsage();
                    return 1;
            }
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine();
            Console.WriteLine("Cryptographic operation failed:");
            Console.WriteLine(ex.Message);
            return 1;
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine(ex.Message);
            return 1;
        }
    }

    private void RunBackend(KeyBackend backend)
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

        PrintKeyInfo(key, configuration);

        _cryptoDemoService.Run(key);
    }

    private void ListAllKeys()
    {
        Console.WriteLine("TPMVault - Stored Keys");
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
            Console.WriteLine("No keys found.");
            return;
        }

        foreach (StoredKeyInfo key in keys)
        {
            Console.WriteLine(
                $"{key.Name}  [{key.Algorithm}]");
        }
    }

    private int HandleDeleteCommand(string[] args)
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
            Console.WriteLine(
                "Backend must be 'software' or 'tpm'.");
            return 1;
        }

        string keyName = args[2];

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
            backend = KeyBackend.Software;
            return true;
        }

        if (value.Equals(
            "tpm",
            StringComparison.OrdinalIgnoreCase))
        {
            backend = KeyBackend.Tpm;
            return true;
        }

        backend = default;
        return false;
    }

    private static void PrintKeyInfo(
        CngKey key,
        KeyConfiguration configuration)
    {
        Console.WriteLine("Key information");
        Console.WriteLine("------------------------");
        Console.WriteLine(
            $"Backend:   {configuration.Backend}");
        Console.WriteLine(
            $"Name:      {key.KeyName}");
        Console.WriteLine(
            $"Algorithm: {key.Algorithm}");
        Console.WriteLine(
            $"Provider:  {key.Provider}");
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
    }
}

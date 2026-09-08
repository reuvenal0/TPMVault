using System.Reflection;

namespace TPMVault.Configuration;

/// <summary>Anchors runtime files to this checkout and rejects ambiguous Windows paths and links.</summary>
internal static class RepositoryPaths
{
    // Rebuild after moving the checkout. No developer-specific path is stored in source.
    internal static readonly string Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
        typeof(RepositoryPaths).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(a => a.Key == "TPMVault.RepositoryRoot").Value!));

    internal static void ValidateComponent(string part)
    {
        string stem = part.Split('.')[0];
        if (string.IsNullOrWhiteSpace(part) || part.EndsWith('.') || part.EndsWith(' ') ||
            part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || part.Contains(':') ||
            new[] { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" }.Contains(stem, StringComparer.OrdinalIgnoreCase) ||
            (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
                (char.IsDigit(stem[3]) || "¹²³".Contains(stem[3]))))
            throw new ArgumentException("Path contains an unsafe filename component.");
    }

    internal static string Resolve(string path, bool allowVault = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            throw new ArgumentException("UNC and device paths are not allowed.");
        foreach (string part in path.Split('\\', '/'))
            if (part != "." && part != ".." && (part.EndsWith(' ') || part.EndsWith('.')))
                throw new ArgumentException("Path components cannot end in spaces or dots.");
        string fullPath = Path.GetFullPath(path, Root);
        if (!fullPath.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Runtime files must remain inside the repository.");
        foreach (string part in Path.GetRelativePath(Root, fullPath).Split(Path.DirectorySeparatorChar))
        {
            ValidateComponent(part);
            if (new[] { ".git", ".codex", ".agents" }.Contains(part, StringComparer.OrdinalIgnoreCase) ||
                (!allowVault && part.Equals("vault", StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Path refers to a protected runtime or repository-internal directory.");
        }
        return fullPath;
    }

    internal static void RejectLinks(string fullPath)
    {
        // Check every existing component before following the next one, including dangling links.
        string current = Root;
        Check(current);
        foreach (string part in Path.GetRelativePath(Root, fullPath).Split(Path.DirectorySeparatorChar))
        {
            current = Path.Combine(current, part);
            if (!Check(current)) break;
        }
        static bool Check(string path)
        {
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new ArgumentException("Runtime paths cannot pass through links or junctions.");
                return true;
            }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
        }
    }
}

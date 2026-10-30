using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecureDesk.Core.Installers;

public sealed class InstallerEntry
{
    public string DisplayName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;

    /// <summary>Empreinte SHA-256 épinglée (hex). Remplie par scripts/pin-installers.ps1 lors de la release.</summary>
    public string Sha256 { get; set; } = string.Empty;

    public string SignerSubjectContains { get; set; } = string.Empty;

    /// <summary>Signature exigée sur le fichier exécuté (pour une archive zip : sur le MSI qu'elle contient).</summary>
    public bool RequireAuthenticode { get; set; }
}

public sealed class InstallerManifest
{
    public InstallerEntry WireGuard { get; set; } = new();
    public InstallerEntry VcRedist { get; set; } = new();
    public InstallerEntry MultiOtp { get; set; } = new();

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true };

    public static InstallerManifest FromJson(string json) =>
        JsonSerializer.Deserialize<InstallerManifest>(json, Json) ?? throw new FormatException("Manifeste des installeurs vide.");

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    /// <summary>Manifeste embarqué dans l'exécutable.</summary>
    public static InstallerManifest Embedded()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("SecureDesk.Core.Installers.installers.json")
            ?? throw new InvalidOperationException("Manifeste des installeurs introuvable.");
        using var reader = new StreamReader(stream);
        return FromJson(reader.ReadToEnd());
    }
}

public static class FileHash
{
    public static string Sha256Hex(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public static bool Matches(string path, string expectedHex) =>
        !string.IsNullOrWhiteSpace(expectedHex) && string.Equals(Sha256Hex(path), expectedHex.Trim(), StringComparison.OrdinalIgnoreCase);
}

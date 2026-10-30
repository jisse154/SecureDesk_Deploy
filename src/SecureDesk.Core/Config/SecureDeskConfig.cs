using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecureDesk.Core.Net;

namespace SecureDesk.Core.Config;

public enum TwoFactorScope
{
    /// <summary>TOTP exigé uniquement pour les connexions distantes (cpus_logon = 1e).</summary>
    RemoteOnly,

    /// <summary>TOTP exigé à distance et à la console (cpus_logon = 0e).</summary>
    RemoteAndLocal,
}

public sealed class UserSpec
{
    public string Name { get; set; } = string.Empty;

    /// <summary>true : créer le compte s'il n'existe pas ; false : le compte doit déjà exister.</summary>
    public bool Create { get; set; } = true;

    public string? FullName { get; set; }
}

public sealed class RedirectionOptions
{
    public bool Clipboard { get; set; }
    public bool Drives { get; set; }
    public bool Printers { get; set; }
}

public sealed class PasswordPolicyOptions
{
    public int MinLength { get; set; } = 14;
    public int LockoutThreshold { get; set; } = 5;
    public int LockoutDurationMinutes { get; set; } = 30;
    public int LockoutWindowMinutes { get; set; } = 30;
}

public sealed class TwoFactorOptions
{
    public TwoFactorScope Scope { get; set; } = TwoFactorScope.RemoteOnly;

    /// <summary>Comptes Windows soumis au 2FA. Vide = tous les comptes déclarés dans Server.Users.</summary>
    public List<string> Accounts { get; set; } = [];

    /// <summary>Délai avant désactivation automatique si confirm-2fa n'est pas lancé.</summary>
    public int ProbationMinutes { get; set; } = 20;
}

public sealed class ServerOptions
{
    public string EndpointHost { get; set; } = string.Empty;
    public int? ListenPort { get; set; }
    public string TunnelSubnet { get; set; } = "10.77.0.0/24";
    public string TunnelName { get; set; } = "securedesk";
    public bool AllowLan { get; set; }

    /// <summary>Sous-réseau LAN autorisé (si AllowLan). Null = détection automatique.</summary>
    public string? LanSubnet { get; set; }

    public List<UserSpec> Users { get; set; } = [];
    public RedirectionOptions Redirections { get; set; } = new();
    public int IdleTimeoutMinutes { get; set; } = 30;
    public int DisconnectedTimeoutMinutes { get; set; } = 60;
    public PasswordPolicyOptions PasswordPolicy { get; set; } = new();

    /// <summary>Ports TCP supplémentaires à protéger comme RDP : serveur web TSplus (qui achemine aussi RDP).</summary>
    public List<int> ExtraProtectedTcpPorts { get; set; } = [80, 443];

    /// <summary>Arrêter le serveur web TSplus (AdminTool.exe /webstop) : portail non utilisé.</summary>
    public bool StopTsplusWebServer { get; set; } = true;

    public TwoFactorOptions TwoFactor { get; set; } = new();
    public string NtpServer { get; set; } = "time.windows.com";
    public int InvitationValidityDays { get; set; } = 7;
}

public sealed class ClientOptions
{
    /// <summary>true : service de tunnel à démarrage automatique ; false : tunnel confié au manager WireGuard (activation manuelle).</summary>
    public bool AutoStartTunnel { get; set; }

    public bool CreateRdpShortcut { get; set; } = true;
    public string RdpShortcutName { get; set; } = "Bureau SecureDesk";
}

public sealed class InstallerOptions
{
    /// <summary>Chemin local du MSI WireGuard (mode hors ligne). Null = téléchargement officiel.</summary>
    public string? WireGuardMsi { get; set; }

    public string? MultiOtpMsi { get; set; }
    public string? VcRedist { get; set; }
    public string? TsplusSetup { get; set; }

    /// <summary>Installation TSplus silencieuse (/verysilent, documenté par TSplus). Désactivée par défaut.</summary>
    public bool TsplusSilent { get; set; }
}

public sealed partial class SecureDeskConfig
{
    public int SchemaVersion { get; set; } = 1;
    public ServerOptions Server { get; set; } = new();
    public ClientOptions Client { get; set; } = new();
    public InstallerOptions Installers { get; set; } = new();

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static SecureDeskConfig FromJson(string json) =>
        JsonSerializer.Deserialize<SecureDeskConfig>(json, JsonOptions) ?? throw new FormatException("Configuration JSON vide.");

    public static SecureDeskConfig Load(string path) => FromJson(File.ReadAllText(path));

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    [GeneratedRegex("^[a-zA-Z0-9_=+.-]{1,32}$", RegexOptions.CultureInvariant)]
    private static partial Regex TunnelNameRegex();

    // Noms de comptes locaux Windows : 1 à 20 caractères, sans "/\[]:;|=,+*?<>@".
    [GeneratedRegex("^[^\"/\\\\\\[\\]:;|=,+*?<>@]{1,20}$", RegexOptions.CultureInvariant)]
    private static partial Regex AccountNameRegex();

    public static bool IsValidAccountName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && AccountNameRegex().IsMatch(name) && !name.EndsWith('.') && name.Trim() == name;

    public IReadOnlyList<string> ValidateServer()
    {
        var errors = new List<string>();
        var s = Server;
        if (!Endpoint.IsValidHost(s.EndpointHost, out var e))
        {
            errors.Add(e);
        }

        if (s.ListenPort is { } p && !Endpoint.IsValidPort(p))
        {
            errors.Add(string.Create(CultureInfo.InvariantCulture, $"Port UDP invalide : {p}."));
        }

        if (!Ipv4Cidr.TryParse(s.TunnelSubnet, out var tunnel, out var te))
        {
            errors.Add(te);
        }
        else if (tunnel.PrefixLength > 29)
        {
            errors.Add("Le sous-réseau du tunnel est trop petit (/29 au maximum).");
        }

        if (!TunnelNameRegex().IsMatch(s.TunnelName))
        {
            errors.Add("Nom de tunnel invalide (1 à 32 caractères parmi a-z A-Z 0-9 _ = + . -).");
        }

        if (s.AllowLan && s.LanSubnet is not null)
        {
            if (!Ipv4Cidr.TryParse(s.LanSubnet, out var lan, out var le))
            {
                errors.Add(le);
            }
            else if (tunnel.PrefixLength > 0 && lan.Overlaps(tunnel))
            {
                errors.Add($"Le sous-réseau LAN {lan} chevauche le sous-réseau du tunnel {tunnel}.");
            }
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in s.Users)
        {
            if (!IsValidAccountName(u.Name))
            {
                errors.Add($"Nom de compte Windows invalide : « {u.Name} ».");
            }
            else if (!names.Add(u.Name))
            {
                errors.Add($"Compte en double : « {u.Name} ».");
            }
        }

        foreach (var a in s.TwoFactor.Accounts.Where(a => !IsValidAccountName(a)))
        {
            errors.Add($"Compte 2FA invalide : « {a} ».");
        }

        if (s.IdleTimeoutMinutes is < 1 or > 1440 || s.DisconnectedTimeoutMinutes is < 1 or > 10080)
        {
            errors.Add("Délais d'expiration hors bornes (inactivité 1–1440 min, déconnexion 1–10080 min).");
        }

        if (s.PasswordPolicy.MinLength is < 8 or > 14)
        {
            // net accounts /minpwlen accepte 0 à 14 sous Windows.
            errors.Add("Longueur minimale de mot de passe : entre 8 et 14 (limite de « net accounts »).");
        }

        if (s.PasswordPolicy.LockoutThreshold is < 1 or > 999)
        {
            errors.Add("Seuil de verrouillage : entre 1 et 999 échecs.");
        }

        if (s.PasswordPolicy.LockoutDurationMinutes < s.PasswordPolicy.LockoutWindowMinutes)
        {
            errors.Add("La durée de verrouillage doit être ≥ à la fenêtre de comptage des échecs (exigence Windows).");
        }

        foreach (var port in s.ExtraProtectedTcpPorts.Where(port => !Endpoint.IsValidPort(port)))
        {
            errors.Add(string.Create(CultureInfo.InvariantCulture, $"Port protégé invalide : {port}."));
        }

        if (s.TwoFactor.ProbationMinutes is < 5 or > 240)
        {
            errors.Add("Durée probatoire du 2FA : entre 5 et 240 minutes.");
        }

        if (s.InvitationValidityDays is < 1 or > 30)
        {
            errors.Add("Validité d'une invitation : entre 1 et 30 jours.");
        }

        return errors;
    }

    /// <summary>Comptes effectivement soumis au 2FA.</summary>
    public IReadOnlyList<string> TwoFactorAccounts() =>
        Server.TwoFactor.Accounts.Count > 0 ? Server.TwoFactor.Accounts : [.. Server.Users.Select(u => u.Name)];
}

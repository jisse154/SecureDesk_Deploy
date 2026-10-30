using SecureDesk.Core.Config;

namespace SecureDesk.Core.Hardening;

public enum RegKind
{
    DWord,
    String,
}

public sealed record RegistryValueSpec(string Path, string Name, RegKind Kind, object Value, string Purpose)
{
    public string Key => $@"HKLM\{Path}\{Name}";
}

public static class HardeningPlan
{
    /// <summary>Stratégies Services Bureau à distance (équivalent GPO, ADMX TerminalServer.admx).</summary>
    public const string TsPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    public const string RdpTcpPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    public static IReadOnlyList<RegistryValueSpec> RdpPolicies(ServerOptions s)
    {
        ArgumentNullException.ThrowIfNull(s);
        static int Off(bool allowed) => allowed ? 0 : 1;
        return
        [
            new(TsPolicyPath, "UserAuthentication", RegKind.DWord, 1, "NLA obligatoire"),
            new(TsPolicyPath, "SecurityLayer", RegKind.DWord, 2, "Couche de sécurité TLS"),
            new(TsPolicyPath, "MinEncryptionLevel", RegKind.DWord, 3, "Niveau de chiffrement élevé"),
            new(TsPolicyPath, "MaxIdleTime", RegKind.DWord, s.IdleTimeoutMinutes * 60_000, "Délai d'expiration des sessions inactives (ms)"),
            new(TsPolicyPath, "MaxDisconnectionTime", RegKind.DWord, s.DisconnectedTimeoutMinutes * 60_000, "Délai de fermeture des sessions déconnectées (ms)"),
            new(TsPolicyPath, "fDisableClip", RegKind.DWord, Off(s.Redirections.Clipboard), "Redirection du presse-papiers"),
            new(TsPolicyPath, "fDisableCdm", RegKind.DWord, Off(s.Redirections.Drives), "Redirection des lecteurs"),
            new(TsPolicyPath, "fDisableCpm", RegKind.DWord, Off(s.Redirections.Printers), "Redirection des imprimantes"),
            new(TsPolicyPath, "fDisableCcm", RegKind.DWord, 1, "Redirection des ports COM"),
            new(TsPolicyPath, "fDisableLPT", RegKind.DWord, 1, "Redirection des ports LPT"),
            new(TsPolicyPath, "fDisablePNPRedir", RegKind.DWord, 1, "Redirection des périphériques Plug and Play"),
        ];
    }

    /// <summary>
    /// Valeur volontairement NON définie : « Toujours demander le mot de passe à la connexion » provoque une seconde
    /// saisie côté serveur malgré NLA, cumulée à l'invite multiOTP. diagnose la signale si elle est présente.
    /// </summary>
    public const string PromptForPasswordValue = "fPromptForPassword";

    /// <summary>Sous-catégories d'audit par GUID (indépendant de la langue de Windows).</summary>
    public static readonly IReadOnlyList<(string Guid, string Name)> AuditSubcategories =
    [
        ("{0CCE9215-69AE-11D9-BED3-505054503030}", "Ouverture de session (4624/4625)"),
        ("{0CCE9216-69AE-11D9-BED3-505054503030}", "Fermeture de session"),
        ("{0CCE9217-69AE-11D9-BED3-505054503030}", "Verrouillage de compte (4625 / 0xC0000234)"),
        ("{0CCE921C-69AE-11D9-BED3-505054503030}", "Autres événements d'ouverture/fermeture de session (reconnexions RDP)"),
    ];

    public const string RemoteConnectionManagerLog = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
    public const int SecurityLogMinBytes = 256 * 1024 * 1024;

    /// <summary>SID bien connus (indépendants de la langue).</summary>
    public const string RemoteDesktopUsersSid = "S-1-5-32-555";

    public const string AdministratorsSid = "S-1-5-32-544";
}

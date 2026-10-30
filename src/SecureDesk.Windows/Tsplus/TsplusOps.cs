using System.Diagnostics;
using Microsoft.Win32;
using SecureDesk.Core.Logging;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.Tsplus;

public sealed record TsplusStatus(bool Installed, string? Version, string? AdminToolPath, IReadOnlyList<string> Services, IReadOnlyList<string> UninstallEntries)
{
    public override string ToString() =>
        Installed ? $"TSplus détecté (version {Version ?? "inconnue"})" : "TSplus non détecté";
}

/// <summary>
/// TSplus : détection et quelques commandes DOCUMENTÉES sur docs.tsplus.net (commands-list, installation, volume-licensing-install).
/// SecureDesk ne télécharge pas TSplus et n'active jamais la licence.
/// </summary>
public sealed class TsplusOps(ILog log, ProcessRunner runner)
{
    /// <summary>Emplacement documenté : « AdminTool.exe … should be located here: C:\Program Files (x86)\TSplus\UserDesktop\files ».</summary>
    public static string FilesDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "TSplus", "UserDesktop", "files");

    public static string AdminTool => Path.Combine(FilesDir, "AdminTool.exe");
    public static string TwoFactorAdmin => Path.Combine(FilesDir, "TwoFactor.Admin.exe");

    public static TsplusStatus Detect()
    {
        var entries = UninstallEntries();
        var adminTool = File.Exists(AdminTool) ? AdminTool : null;
        string? version = null;
        if (adminTool is not null)
        {
            version = FileVersionInfo.GetVersionInfo(adminTool).ProductVersion;
        }

        version ??= entries.Select(e => e.Version).FirstOrDefault(v => !string.IsNullOrEmpty(v));
        // Heuristique signalée comme telle : les noms de services TSplus ne sont pas documentés.
        var services = Services.FindByDisplayName("TSplus").Select(s => $"{s.DisplayName} ({s.Status})").ToList();
        return new TsplusStatus(adminTool is not null || entries.Count > 0, version, adminTool, services, [.. entries.Select(e => e.Name)]);
    }

    private static List<(string Name, string? Version)> UninstallEntries()
    {
        var result = new List<(string, string?)>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (root is null)
            {
                continue;
            }

            foreach (var sub in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(sub);
                if (k?.GetValue("DisplayName") is string name && name.Contains("TSplus", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add((name, k.GetValue("DisplayVersion") as string));
                }
            }
        }

        return result;
    }

    /// <summary>Installation silencieuse : « Execute the setup program silently with this command : /verysilent » (docs TSplus).</summary>
    public void InstallSilently(string setupPath)
    {
        if (!Authenticode.Verify(setupPath).Valid)
        {
            throw new InstallerVerificationException("L'installeur TSplus fourni n'a pas de signature Authenticode valide : installation refusée.");
        }

        log.Info("Installation silencieuse de TSplus (/verysilent). L'installeur télécharge le produit : connexion Internet requise.");
        runner.RunChecked(setupPath, ["/verysilent"], timeout: TimeSpan.FromMinutes(45));
        log.Warn("TSplus exige un redémarrage de Windows avant utilisation (documentation TSplus).");
    }

    /// <summary>Commandes documentées « AdminTool.exe /webstop | /webstart ».</summary>
    public void StopWebServer() => runner.RunChecked(AdminTool, ["/webstop"], timeout: TimeSpan.FromMinutes(2));

    public void StartWebServer() => runner.RunChecked(AdminTool, ["/webstart"], timeout: TimeSpan.FromMinutes(2));

    /// <summary>Le serveur web TSplus écoute-t-il sur l'un des ports donnés ?</summary>
    public static bool WebServerListening(IEnumerable<int> ports) => ports.Any(p => SystemInfo.TcpListeners(p).Count > 0);

    /// <summary>2FA TSplus (non utilisé) : « TwoFactor.Admin.exe /getusers » renvoie la liste JSON des utilisateurs configurés.</summary>
    public bool? TsplusTwoFactorHasUsers()
    {
        if (!File.Exists(TwoFactorAdmin))
        {
            return null;
        }

        var r = runner.Run(TwoFactorAdmin, ["/getusers"], timeout: TimeSpan.FromMinutes(1));
        if (!r.Ok)
        {
            return null;
        }

        var json = r.StdOut.Trim();
        return !(json.Length == 0 || json == "[]" || json == "{}");
    }

    public static IReadOnlyList<string> ManualInstallInstructions() =>
    [
        "1. Lancez l'installeur TSplus Remote Access que vous avez acheté (Setup-TSplus.exe), en administrateur.",
        "2. Choisissez le mode « Advanced » si vous voulez ne PAS installer l'essai TSplus Advanced Security.",
        "3. Acceptez le contrat, laissez l'installation se terminer, puis REDÉMARREZ le PC (exigé par TSplus).",
        "4. Ouvrez l'AdminTool (C:\\Program Files (x86)\\TSplus\\UserDesktop\\files\\AdminTool.exe) → onglet License → « Activate your license » et saisissez votre clé.",
        "5. Revenez dans SecureDesk et confirmez : l'outil revérifie la détection.",
    ];

    public static IReadOnlyList<string> SecuritySettingsInstructions() =>
    [
        "AdminTool → Sessions → Permissions : laissez « Allow access from Microsoft RDP client for everyone » (SecureDesk utilise mstsc).",
        "AdminTool → Sessions → Permissions : cochez « Deny access from Outside » (seules les IP privées, dont le tunnel 10.77.x.x, sont acceptées).",
        "N'activez PAS le module Two-Factor Authentication de TSplus (le 2FA est assuré par multiOTP à l'ouverture de session Windows).",
        "Le portail web TSplus n'est pas utilisé : SecureDesk arrête le serveur web (AdminTool.exe /webstop) et bloque ses ports hors tunnel, car TSplus y achemine aussi RDP.",
    ];
}

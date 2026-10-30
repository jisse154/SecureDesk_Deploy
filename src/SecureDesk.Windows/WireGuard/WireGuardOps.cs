using System.Globalization;
using System.ServiceProcess;
using SecureDesk.Core.Installers;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Security;
using SecureDesk.Core.WireGuard;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.WireGuard;

/// <summary>
/// Pilotage de WireGuard pour Windows, uniquement via les interfaces documentées (docs/enterprise.md) :
/// MSI (DO_NOT_LAUNCH), wireguard.exe /installtunnelservice, /uninstalltunnelservice, /installmanagerservice, wg.exe.
/// </summary>
public sealed class WireGuardOps(ILog log, ProcessRunner runner) : IWgKeyGenerator
{
    public static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard");
    public static string WireGuardExe => Path.Combine(InstallDir, "wireguard.exe");
    public static string WgExe => Path.Combine(InstallDir, "wg.exe");

    /// <summary>Dossier surveillé par le manager service : un .conf déposé y est chiffré en .conf.dpapi puis supprimé.</summary>
    public static string ManagerConfigDir => Path.Combine(InstallDir, "Data", "Configurations");

    public const string ManagerServiceName = "WireGuardManager";

    public static string TunnelServiceName(string tunnel) => "WireGuardTunnel$" + tunnel;

    public static string ConfPath(string tunnel) => Path.Combine(SecureFiles.WireGuardDir, tunnel + ".conf");

    public static bool IsInstalled => File.Exists(WireGuardExe) && File.Exists(WgExe);

    /// <summary>Installe WireGuard si nécessaire. Retourne true si SecureDesk vient de l'installer.</summary>
    public bool EnsureInstalled(InstallerManifest manifest, string? localMsi, string? sha256 = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (IsInstalled)
        {
            log.Info("WireGuard est déjà installé.");
            return false;
        }

        var source = new InstallerSource(log, runner);
        var msi = source.Acquire(manifest.WireGuard, localMsi, sha256);
        source.InstallMsi(msi, ["DO_NOT_LAUNCH=1"], "wireguard-install.log");
        if (!IsInstalled)
        {
            throw new InvalidOperationException("WireGuard ne semble pas installé après exécution du MSI.");
        }

        // Le binaire installé doit lui aussi être signé par l'éditeur attendu.
        if (!Authenticode.IsTrusted(WireGuardExe, manifest.WireGuard.SignerSubjectContains, out var sig))
        {
            throw new InstallerVerificationException($"wireguard.exe installé : {sig}");
        }

        return true;
    }

    // ---------- Clés (pipes stdin/stdout : jamais d'argument ni de fichier temporaire) ----------

    public WgKeyPair GenerateKeyPair()
    {
        var priv = runner.Run(WgExe, ["genkey"], logOutput: false);
        if (!priv.Ok)
        {
            throw new InvalidOperationException("wg genkey a échoué.");
        }

        var privateKey = new WgSecretKey(priv.StdOut.Trim());
        return new WgKeyPair(privateKey, DerivePublicKey(privateKey));
    }

    public WgPublicKey DerivePublicKey(WgSecretKey privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var pub = runner.Run(WgExe, ["pubkey"], stdin: privateKey.Reveal() + "\n", logOutput: false);
        if (!pub.Ok)
        {
            throw new InvalidOperationException("wg pubkey a échoué.");
        }

        return new WgPublicKey(pub.StdOut.Trim());
    }

    public WgSecretKey GeneratePresharedKey()
    {
        var psk = runner.Run(WgExe, ["genpsk"], logOutput: false);
        if (!psk.Ok)
        {
            throw new InvalidOperationException("wg genpsk a échoué.");
        }

        return new WgSecretKey(psk.StdOut.Trim());
    }

    // ---------- Configuration ----------

    public static bool ConfExists(string tunnel) => File.Exists(ConfPath(tunnel));

    public static WgConfig ReadConf(string tunnel) => WgConfig.Parse(File.ReadAllText(ConfPath(tunnel)));

    public void WriteConf(string tunnel, WgConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        SecureFiles.WriteProtected(ConfPath(tunnel), config.Render());
        log.Info($"Configuration du tunnel écrite (ACL SYSTEM + Administrateurs) : {ConfPath(tunnel)}");
    }

    // ---------- Service de tunnel ----------

    public static bool TunnelServiceExists(string tunnel) => Services.Exists(TunnelServiceName(tunnel));

    public void InstallTunnelService(string tunnel, bool automaticStart)
    {
        if (!TunnelServiceExists(tunnel))
        {
            runner.RunChecked(WireGuardExe, ["/installtunnelservice", ConfPath(tunnel)]);
            WaitForService(TunnelServiceName(tunnel), TimeSpan.FromSeconds(30));
        }

        Services.SetStartMode(runner, TunnelServiceName(tunnel), automaticStart);
        log.Info($"Service {TunnelServiceName(tunnel)} : démarrage {(automaticStart ? "automatique" : "manuel")}.");
    }

    public void UninstallTunnelService(string tunnel)
    {
        if (TunnelServiceExists(tunnel))
        {
            runner.RunChecked(WireGuardExe, ["/uninstalltunnelservice", tunnel]);
        }
    }

    /// <summary>Le service relit le fichier .conf à son démarrage : un redémarrage applique les changements de pairs.</summary>
    public void RestartTunnel(string tunnel)
    {
        Services.Restart(TunnelServiceName(tunnel));
        log.Info($"Tunnel {tunnel} redémarré.");
    }

    public static ServiceControllerStatus? TunnelStatus(string tunnel) => Services.Status(TunnelServiceName(tunnel));

    // ---------- Manager (client en mode manuel, configuration chiffrée DPAPI) ----------

    public void EnsureManagerService()
    {
        if (!Services.Exists(ManagerServiceName))
        {
            runner.RunChecked(WireGuardExe, ["/installmanagerservice"]);
            WaitForService(ManagerServiceName, TimeSpan.FromSeconds(30));
        }
    }

    /// <summary>
    /// Confie la configuration au manager : on dépose le .conf dans Data\Configurations, le manager le chiffre
    /// (.conf.dpapi), le rend illisible hors SYSTEM et supprime l'original (comportement documenté).
    /// </summary>
    public void ImportIntoManager(string tunnel, WgConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        EnsureManagerService();
        Directory.CreateDirectory(ManagerConfigDir);
        var target = Path.Combine(ManagerConfigDir, tunnel + ".conf");
        SecureFiles.WriteProtected(target, config.Render());
        var encrypted = target + ".dpapi";
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline && (File.Exists(target) || !File.Exists(encrypted)))
        {
            Thread.Sleep(500);
        }

        if (!File.Exists(encrypted))
        {
            SecureFiles.BestEffortWipe(target);
            throw new InvalidOperationException("Le manager WireGuard n'a pas pris en charge la configuration (fichier .conf.dpapi absent).");
        }

        log.Info("Configuration confiée au manager WireGuard (chiffrée DPAPI). Activez le tunnel depuis l'icône WireGuard.");
    }

    public static bool ManagerHasTunnel(string tunnel) => File.Exists(Path.Combine(ManagerConfigDir, tunnel + ".conf.dpapi"));

    public void RemoveFromManager(string tunnel)
    {
        var path = Path.Combine(ManagerConfigDir, tunnel + ".conf.dpapi");
        if (File.Exists(path))
        {
            // Si le tunnel est actif via le manager, le service de tunnel porte le même nom : on l'arrête d'abord.
            UninstallTunnelService(tunnel);
            File.Delete(path);
        }
    }

    // ---------- État ----------

    /// <summary>Date du dernier handshake par clé publique de pair (wg show &lt;tunnel&gt; latest-handshakes).</summary>
    public IReadOnlyDictionary<string, DateTimeOffset?> LatestHandshakes(string tunnel)
    {
        var r = runner.Run(WgExe, ["show", tunnel, "latest-handshakes"]);
        var result = new Dictionary<string, DateTimeOffset?>(StringComparer.Ordinal);
        if (!r.Ok)
        {
            return result;
        }

        foreach (var line in r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split('\t', ' ');
            if (parts.Length >= 2 && long.TryParse(parts[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var unix))
            {
                result[parts[0]] = unix == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(unix);
            }
        }

        return result;
    }

    private static void WaitForService(string name, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (Services.Exists(name))
            {
                return;
            }

            Thread.Sleep(500);
        }

        throw new InvalidOperationException($"Le service {name} n'est pas apparu.");
    }
}

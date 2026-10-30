using Microsoft.Win32;
using SecureDesk.Core.Logging;
using SecureDesk.Core.State;
using SecureDesk.Windows.Firewall;
using SecureDesk.Windows.MultiOtp;
using SecureDesk.Windows.Sys;
using SecureDesk.Windows.Tsplus;
using SecureDesk.Windows.WireGuard;

namespace SecureDesk.Windows.Ops;

/// <summary>
/// Rollback complet : tunnel, règles de pare-feu, multiOTP, réglages modifiés (valeurs d'origine mémorisées).
/// Les comptes et TSplus ne sont jamais supprimés sans demande explicite (TSplus : jamais).
/// </summary>
public sealed class Uninstaller(Context ctx)
{
    public void Run(bool removeAccounts)
    {
        var st = ctx.State;
        var plan = new List<string>();
        if (MultiOtpOps.Status().Installed)
        {
            plan.Add(st.Rollback.Any(r => r.Key == "installed:multiotp") ? "Désactiver puis désinstaller multiOTP Credential Provider" : "Désactiver multiOTP (installé hors SecureDesk : non désinstallé)");
        }

        var tunnel = new[] { st.Server?.TunnelName, st.Client?.TunnelName, ctx.Config.Server.TunnelName }.First(t => !string.IsNullOrWhiteSpace(t))!;
        plan.Add($"Supprimer le tunnel WireGuard « {tunnel} » et sa configuration");
        plan.Add("Supprimer les règles de pare-feu « SecureDesk-* »");
        plan.AddRange(st.Rollback.AsEnumerable().Reverse().Where(r => r.Kind != "account-created" || removeAccounts).Select(Describe).Where(d => d is not null)!);
        plan.Add("Supprimer %ProgramData%\\SecureDesk (sauf les journaux) et %ProgramFiles%\\SecureDesk");
        ctx.Ui.Show("Désinstallation SecureDesk", plan);
        if (ctx.DryRun || !ctx.Ui.Confirm("Procéder à la désinstallation ?"))
        {
            return;
        }

        // 1. 2FA d'abord : jamais de Credential Provider actif sans l'outil pour le désactiver.
        var otp = new MultiOtpOps(ctx.Log, ctx.Runner);
        if (MultiOtpOps.Status().Installed)
        {
            otp.SetDisabled();
            Try(() => new SelfInstall(ctx.Log, ctx.Runner).CancelProbation());
            if (st.Rollback.Any(r => r.Key == "installed:multiotp"))
            {
                UninstallProduct("multiOTP", "multiotp-uninstall.log");
            }
        }

        // 2. Tunnel.
        var wg = new WireGuardOps(ctx.Log, ctx.Runner);
        if (WireGuardOps.IsInstalled)
        {
            Try(() => wg.RemoveFromManager(tunnel));
            Try(() => wg.UninstallTunnelService(tunnel));
        }

        if (WireGuardOps.ConfExists(tunnel))
        {
            SecureFiles.BestEffortWipe(WireGuardOps.ConfPath(tunnel));
        }

        // 3. Pare-feu.
        new FirewallOps(ctx.Log, ctx.Runner).RemoveAllOwned();

        // 4. Réglages, dans l'ordre inverse.
        var policies = new Policies(ctx.Log, ctx.Runner);
        foreach (var r in st.Rollback.AsEnumerable().Reverse().ToList())
        {
            var done = Try(() =>
            {
                switch (r.Kind)
                {
                    case RegistryOps.RollbackKind: RegistryOps.Restore(r); break;
                    case Policies.SeceditKind: policies.RestoreSystemAccess(r); break;
                    case Policies.AuditKind: policies.RestoreAudit(r); break;
                    case Policies.EventLogKind: policies.RestoreEventLog(r); break;
                    case Policies.W32TimeKind: policies.RestoreTimeSync(r); break;
                    case "tsplus-web":
                        if (File.Exists(TsplusOps.AdminTool))
                        {
                            new TsplusOps(ctx.Log, ctx.Runner).StartWebServer();
                        }

                        break;
                    case "account-created":
                        if (removeAccounts)
                        {
                            RemoveAccount(r.Data["name"]!);
                        }
                        else
                        {
                            return false;
                        }

                        break;
                    case "installed":
                        if (r.Data.GetValueOrDefault("product") == "WireGuard")
                        {
                            UninstallProduct("WireGuard", "wireguard-uninstall.log");
                        }

                        break;
                    default:
                        break;
                }

                return true;
            });
            if (done)
            {
                st.Rollback.Remove(r);
            }
        }

        // 5. Fichiers.
        foreach (var f in Directory.Exists(SecureFiles.SecretsDir) ? Directory.GetFiles(SecureFiles.SecretsDir) : [])
        {
            SecureFiles.BestEffortWipe(f);
        }

        foreach (var dir in new[] { SecureFiles.SecretsDir, SecureFiles.WireGuardDir, InstallerSource.DownloadDir })
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }

        Try(() => new SelfInstall(ctx.Log, ctx.Runner).Remove());
        var remaining = st.Rollback.Where(r => r.Kind == "account-created").ToList();
        if (remaining.Count == 0 && File.Exists(SecureFiles.StatePath))
        {
            File.Delete(SecureFiles.StatePath);
        }
        else
        {
            // On conserve la trace des comptes créés pour un éventuel « uninstall --remove-accounts » ultérieur.
            var keep = new SecureDeskState { Rollback = remaining };
            ctx.Store.Save(keep);
        }

        ctx.Ui.Info($"Désinstallation terminée. Journaux conservés dans {SecureFiles.LogsDir}. TSplus et les comptes{(removeAccounts ? " non créés par SecureDesk" : string.Empty)} sont conservés.");
    }

    private static string? Describe(RollbackRecord r) => r.Kind switch
    {
        RegistryOps.RollbackKind => $"Restaurer {r.Data["path"]}\\{r.Data["name"]}",
        Policies.SeceditKind => "Restaurer la stratégie de mots de passe et de verrouillage",
        Policies.AuditKind => $"Restaurer l'audit {r.Data["guid"]}",
        Policies.EventLogKind => $"Restaurer le journal {r.Data["log"]}",
        Policies.W32TimeKind => "Restaurer la configuration de l'heure Windows",
        "tsplus-web" => "Redémarrer le serveur web TSplus",
        "account-created" => $"SUPPRIMER le compte « {r.Data["name"]} » (demandé par --remove-accounts)",
        "installed" => r.Data.GetValueOrDefault("product") == "WireGuard" ? "Désinstaller WireGuard (installé par SecureDesk)" : null,
        _ => null,
    };

    private void RemoveAccount(string name)
    {
        ctx.Runner.RunChecked(ProcessRunner.SystemExe("net.exe"), ["user", name, "/delete"]);
        ctx.Log.Info($"Compte « {name} » supprimé (le profil C:\\Users\\{name} reste à supprimer manuellement si souhaité).");
    }

    private void UninstallProduct(string displayNameContains, string logName)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            foreach (var sub in root?.GetSubKeyNames() ?? [])
            {
                using var k = root!.OpenSubKey(sub);
                if (sub.StartsWith('{') && k?.GetValue("DisplayName") is string name && name.Contains(displayNameContains, StringComparison.OrdinalIgnoreCase)
                    && !name.Contains("TSplus", StringComparison.OrdinalIgnoreCase))
                {
                    new InstallerSource(ctx.Log, ctx.Runner).UninstallMsiByProductCode(sub, logName);
                    ctx.Log.Info($"{name} désinstallé.");
                    return;
                }
            }
        }
    }

    private bool Try(Func<bool> action)
    {
        try
        {
            return action();
        }
#pragma warning disable CA1031 // La désinstallation continue au mieux et signale chaque échec.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            ctx.Ui.Warn("Étape de désinstallation en échec (à vérifier) : " + ex.Message);
            return false;
        }
    }

    private void Try(Action action) => Try(() =>
    {
        action();
        return true;
    });
}

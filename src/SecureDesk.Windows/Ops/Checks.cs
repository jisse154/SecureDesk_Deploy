using System.Globalization;
using SecureDesk.Core.Time;
using SecureDesk.Windows.Sys;
using SecureDesk.Windows.Tsplus;

namespace SecureDesk.Windows.Ops;

public enum CheckLevel
{
    Ok,
    Warning,
    Blocking,
}

public sealed record CheckItem(string Name, CheckLevel Level, string Detail)
{
    public override string ToString() => $"[{Label}] {Name} : {Detail}";

    public string Label => Level switch
    {
        CheckLevel.Ok => "OK",
        CheckLevel.Warning => "ATTENTION",
        _ => "BLOQUANT",
    };
}

/// <summary>Pré-vérifications (serveur et client). Lecture seule.</summary>
public static class Checks
{
    /// <summary>Réservé aux tests d'intégration sur les runners Windows Server de GitHub Actions.</summary>
    private static bool AllowAnyEditionForTests => Environment.GetEnvironmentVariable("SECUREDESK_TEST_ALLOW_ANY_EDITION") == "1";

    public static IReadOnlyList<CheckItem> Server(Context ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        var items = new List<CheckItem>();
        items.Add(SystemInfo.IsAdministrator()
            ? new("Droits administrateur", CheckLevel.Ok, "processus élevé")
            : new("Droits administrateur", CheckLevel.Blocking, "relancez SecureDesk en tant qu'administrateur"));

        var edition = SystemInfo.EditionId ?? "inconnue";
        items.Add(!SystemInfo.IsWindows11
            ? new("Version de Windows", CheckLevel.Warning, $"build {SystemInfo.Build} : Windows 11 attendu")
            : new("Version de Windows", CheckLevel.Ok, $"Windows 11 {SystemInfo.DisplayVersion} (build {SystemInfo.Build})"));
        items.Add(SystemInfo.IsProOrBetter
            ? new("Édition Windows", CheckLevel.Ok, edition)
            : new("Édition Windows", AllowAnyEditionForTests ? CheckLevel.Warning : CheckLevel.Blocking, $"{edition} : Windows 11 Pro requis côté serveur (Bureau à distance hôte)"));

        var reboot = SystemInfo.PendingRebootReasons();
        items.Add(reboot.Count == 0
            ? new("Redémarrage en attente", CheckLevel.Ok, "aucun")
            : new("Redémarrage en attente", CheckLevel.Warning, string.Join(", ", reboot) + " : redémarrez avant de continuer si possible"));

        items.AddRange(Resources());

        var ts = TsplusOps.Detect();
        items.Add(ts.Installed
            ? new("TSplus", CheckLevel.Ok, $"{ts}. Services : {(ts.Services.Count == 0 ? "aucun identifié (heuristique)" : string.Join(", ", ts.Services))}")
            : new("TSplus", CheckLevel.Warning, "non détecté : installation guidée proposée (étape TSplus)"));

        var lan = SystemInfo.DetectLan();
        items.Add(lan is null
            ? new("Réseau local", CheckLevel.Warning, "aucune interface avec passerelle détectée")
            : new("Réseau local", CheckLevel.Ok, $"{lan.Address} ({lan.Subnet}) via {lan.InterfaceName}, passerelle {lan.Gateway}"));

        items.Add(SystemInfo.IsRemoteSession()
            ? new("Type de session", CheckLevel.Warning, "session À DISTANCE : l'activation du 2FA sera refusée sans --i-have-console-access")
            : new("Type de session", CheckLevel.Ok, "session locale (console)"));

        items.Add(SystemInfo.RdpEnabled()
            ? new("Bureau à distance", CheckLevel.Ok, string.Create(CultureInfo.InvariantCulture, $"activé, port {SystemInfo.RdpPort()}"))
            : new("Bureau à distance", CheckLevel.Warning, "désactivé (TSplus l'active normalement à l'installation)"));

        items.Add(Clock(ctx.Config.Server.NtpServer));
        items.Add(BitLocker());
        return items;
    }

    public static IReadOnlyList<CheckItem> Client()
    {
        var items = new List<CheckItem>
        {
            SystemInfo.IsAdministrator()
                ? new("Droits administrateur", CheckLevel.Ok, "processus élevé")
                : new("Droits administrateur", CheckLevel.Blocking, "relancez SecureDesk en tant qu'administrateur"),
            new("Version de Windows", CheckLevel.Ok, $"{SystemInfo.EditionId} build {SystemInfo.Build}"),
            BitLocker(clientSide: true),
        };
        return items;
    }

    public static IEnumerable<CheckItem> Resources()
    {
        var (total, avail) = SystemInfo.Memory();
        var gb = total / 1024d / 1024 / 1024;
        var availGb = avail / 1024d / 1024 / 1024;
        yield return gb < 8
            ? new("Mémoire", CheckLevel.Warning, string.Create(CultureInfo.InvariantCulture, $"{gb:0.0} Go ({availGb:0.0} Go libres) : 8 Go recommandés pour deux sessions"))
            : new("Mémoire", CheckLevel.Ok, string.Create(CultureInfo.InvariantCulture, $"{gb:0.0} Go ({availGb:0.0} Go libres)"));
        var cpu = SystemInfo.CpuLoadPercent();
        yield return SystemInfo.LogicalProcessors < 4 || cpu > 85
            ? new("Processeur", CheckLevel.Warning, string.Create(CultureInfo.InvariantCulture, $"{SystemInfo.LogicalProcessors} cœurs logiques, charge {cpu:0} %"))
            : new("Processeur", CheckLevel.Ok, string.Create(CultureInfo.InvariantCulture, $"{SystemInfo.LogicalProcessors} cœurs logiques, charge {cpu:0} %"));
    }

    public static CheckItem Clock(string ntpServer)
    {
        try
        {
            var offset = Sntp.MeasureOffsetAsync(ntpServer, TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
            var seconds = Math.Abs(offset.TotalSeconds);
            return seconds > Sntp.MaxAllowedDrift.TotalSeconds
                ? new("Horloge", CheckLevel.Blocking, string.Create(CultureInfo.InvariantCulture, $"dérive de {offset.TotalSeconds:+0.0;-0.0;0.0} s par rapport à {ntpServer} (> 30 s) : les codes TOTP seraient refusés"))
                : new("Horloge", CheckLevel.Ok, string.Create(CultureInfo.InvariantCulture, $"dérive {Math.Round(offset.TotalSeconds, 2) + 0.0:+0.00;-0.00;0.00} s par rapport à {ntpServer}"));
        }
#pragma warning disable CA1031 // Toute erreur réseau devient un avertissement lisible.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return new("Horloge", CheckLevel.Warning, $"mesure impossible auprès de {ntpServer} ({ex.Message}) ; vérifiez que l'heure Windows est synchronisée");
        }
    }

    public static CheckItem BitLocker(bool clientSide = false)
    {
        var status = Policies.BitLockerProtectionStatus();
        var why = clientSide ? " — il protège la clé privée WireGuard en cas de vol du PC" : " — il protège les données sensibles et les graines TOTP";
        return status == 1
            ? new("BitLocker", CheckLevel.Ok, Policies.DescribeBitLocker(status))
            : new("BitLocker", CheckLevel.Warning, Policies.DescribeBitLocker(status) + why);
    }
}

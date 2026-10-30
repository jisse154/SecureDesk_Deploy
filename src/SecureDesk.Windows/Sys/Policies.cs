using System.Globalization;
using System.Management;
using System.Text;
using SecureDesk.Core.Config;
using SecureDesk.Core.Logging;
using SecureDesk.Core.State;

namespace SecureDesk.Windows.Sys;

/// <summary>Stratégies locales : mots de passe/verrouillage (secedit), audit (auditpol), journaux (wevtutil), heure (w32tm), BitLocker (WMI).</summary>
public sealed class Policies(ILog log, ProcessRunner runner)
{
    public const string SeceditKind = "secedit";
    public const string AuditKind = "auditpol";
    public const string EventLogKind = "eventlog";
    public const string W32TimeKind = "w32time";

    private static readonly string[] AccessKeys = ["MinimumPasswordLength", "PasswordComplexity", "LockoutBadCount", "ResetLockoutCount", "LockoutDuration"];

    // ---------- Mots de passe et verrouillage (secedit, clés INF fixes indépendantes de la langue) ----------

    public IReadOnlyDictionary<string, int> ReadSystemAccess()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "sd-secedit-" + Guid.NewGuid().ToString("N") + ".inf");
        try
        {
            runner.RunChecked(ProcessRunner.SystemExe("secedit.exe"), ["/export", "/cfg", tmp, "/areas", "SECURITYPOLICY", "/quiet"]);
            return ParseSystemAccess(File.ReadAllText(tmp, Encoding.Unicode));
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    internal static Dictionary<string, int> ParseSystemAccess(string inf)
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var inSection = false;
        foreach (var raw in inf.ReplaceLineEndings("\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('['))
            {
                inSection = line.Equals("[System Access]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (inSection && eq > 0 && int.TryParse(line[(eq + 1)..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v))
            {
                result[line[..eq].Trim()] = v;
            }
        }

        return result;
    }

    public static IReadOnlyDictionary<string, int> Wanted(PasswordPolicyOptions p)
    {
        ArgumentNullException.ThrowIfNull(p);
        return new Dictionary<string, int>
        {
            ["MinimumPasswordLength"] = p.MinLength,
            ["PasswordComplexity"] = 1,
            ["LockoutBadCount"] = p.LockoutThreshold,
            ["ResetLockoutCount"] = p.LockoutWindowMinutes,
            ["LockoutDuration"] = p.LockoutDurationMinutes,
        };
    }

    public bool SystemAccessMatches(PasswordPolicyOptions p)
    {
        var current = ReadSystemAccess();
        return Wanted(p).All(kv => current.TryGetValue(kv.Key, out var v) && v == kv.Value);
    }

    public void ApplySystemAccess(PasswordPolicyOptions p, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var current = ReadSystemAccess();
        state.RecordOriginal("secedit:system-access", SeceditKind,
            AccessKeys.ToDictionary(k => k, k => current.TryGetValue(k, out var v) ? v.ToString(CultureInfo.InvariantCulture) : null));
        Configure(Wanted(p));
        log.Info("Stratégie de mots de passe et de verrouillage appliquée.");
    }

    public void RestoreSystemAccess(RollbackRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var values = record.Data.Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => int.Parse(kv.Value!, CultureInfo.InvariantCulture));
        Configure(values);
    }

    private void Configure(IReadOnlyDictionary<string, int> values)
    {
        var dir = Path.Combine(Path.GetTempPath(), "sd-secedit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var inf = Path.Combine(dir, "policy.inf");
            var sb = new StringBuilder();
            sb.AppendLine("[Unicode]").AppendLine("Unicode=yes").AppendLine("[System Access]");
            // Ordre : la fenêtre de comptage doit être ≤ à la durée de verrouillage (exigence Windows).
            foreach (var k in AccessKeys.Where(values.ContainsKey))
            {
                sb.Append(k).Append(" = ").AppendLine(values[k].ToString(CultureInfo.InvariantCulture));
            }

            sb.AppendLine("[Version]").AppendLine("signature=\"$CHICAGO$\"").AppendLine("Revision=1");
            File.WriteAllText(inf, sb.ToString(), Encoding.Unicode);
            runner.RunChecked(ProcessRunner.SystemExe("secedit.exe"),
                ["/configure", "/db", Path.Combine(dir, "policy.sdb"), "/cfg", inf, "/areas", "SECURITYPOLICY", "/quiet"]);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    // ---------- Audit (auditpol, par GUID ; lecture via /backup qui donne une valeur numérique) ----------

    public IReadOnlyDictionary<string, int> ReadAudit()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "sd-audit-" + Guid.NewGuid().ToString("N") + ".csv");
        try
        {
            runner.RunChecked(ProcessRunner.SystemExe("auditpol.exe"), ["/backup", "/file:" + tmp]);
            return ParseAuditBackup(File.ReadAllText(tmp));
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    /// <summary>CSV : Machine,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value.</summary>
    internal static Dictionary<string, int> ParseAuditBackup(string csv)
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in csv.ReplaceLineEndings("\n").Split('\n').Skip(1))
        {
            var cols = line.Split(',');
            if (cols.Length >= 7 && cols[3].StartsWith('{') && int.TryParse(cols[6].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v))
            {
                result[cols[3].Trim()] = v;
            }
        }

        return result;
    }

    /// <summary>Valeur 3 = succès et échec.</summary>
    public bool AuditMatches(IEnumerable<string> guids)
    {
        var current = ReadAudit();
        return guids.All(g => current.TryGetValue(g, out var v) && v == 3);
    }

    public void EnableAudit(IEnumerable<string> guids, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(guids);
        ArgumentNullException.ThrowIfNull(state);
        var current = ReadAudit();
        foreach (var g in guids)
        {
            state.RecordOriginal("audit:" + g, AuditKind, new Dictionary<string, string?>
            {
                ["guid"] = g,
                ["value"] = current.TryGetValue(g, out var v) ? v.ToString(CultureInfo.InvariantCulture) : "0",
            });
            SetAudit(g, 3);
        }

        log.Info("Audit des ouvertures de session activé (succès et échecs).");
    }

    public void RestoreAudit(RollbackRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        SetAudit(record.Data["guid"]!, int.Parse(record.Data["value"] ?? "0", CultureInfo.InvariantCulture));
    }

    private void SetAudit(string guid, int value) =>
        runner.RunChecked(ProcessRunner.SystemExe("auditpol.exe"),
            ["/set", "/subcategory:" + guid, "/success:" + ((value & 1) != 0 ? "enable" : "disable"), "/failure:" + ((value & 2) != 0 ? "enable" : "disable")]);

    // ---------- Journaux d'événements ----------

    public static long? SecurityLogMaxSize() =>
        RegistryOps.Read(@"SYSTEM\CurrentControlSet\Services\EventLog\Security", "MaxSize") is int i ? (uint)i : null;

    public void EnsureSecurityLogSize(long minBytes, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var current = SecurityLogMaxSize();
        state.RecordOriginal("eventlog:Security", EventLogKind, new Dictionary<string, string?>
        {
            ["log"] = "Security",
            ["maxSize"] = current?.ToString(CultureInfo.InvariantCulture),
        });
        runner.RunChecked(ProcessRunner.SystemExe("wevtutil.exe"), ["sl", "Security", "/ms:" + minBytes.ToString(CultureInfo.InvariantCulture)]);
    }

    public bool IsLogEnabled(string logName)
    {
        var r = runner.Run(ProcessRunner.SystemExe("wevtutil.exe"), ["gl", logName]);
        return r.Ok && r.StdOut.Split('\n').Any(l => l.Trim().Equals("enabled: true", StringComparison.OrdinalIgnoreCase));
    }

    public void EnableLog(string logName, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        state.RecordOriginal("eventlog-enabled:" + logName, EventLogKind, new Dictionary<string, string?>
        {
            ["log"] = logName,
            ["enabled"] = IsLogEnabled(logName) ? "true" : "false",
        });
        runner.RunChecked(ProcessRunner.SystemExe("wevtutil.exe"), ["sl", logName, "/e:true"]);
    }

    public void RestoreEventLog(RollbackRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var logName = record.Data["log"]!;
        if (record.Data.TryGetValue("maxSize", out var size) && size is not null)
        {
            runner.Run(ProcessRunner.SystemExe("wevtutil.exe"), ["sl", logName, "/ms:" + size]);
        }

        if (record.Data.TryGetValue("enabled", out var enabled) && enabled is not null)
        {
            runner.Run(ProcessRunner.SystemExe("wevtutil.exe"), ["sl", logName, "/e:" + enabled]);
        }
    }

    // ---------- Synchronisation horaire ----------

    private const string W32TimeParams = @"SYSTEM\CurrentControlSet\Services\W32Time\Parameters";

    public static bool TimeSyncConfigured(string ntpServer) =>
        Services.StartMode("W32Time") == System.ServiceProcess.ServiceStartMode.Automatic
        && Services.Status("W32Time") == System.ServiceProcess.ServiceControllerStatus.Running
        && string.Equals(RegistryOps.ReadString(W32TimeParams, "Type"), "NTP", StringComparison.OrdinalIgnoreCase)
        && (RegistryOps.ReadString(W32TimeParams, "NtpServer") ?? string.Empty).Contains(ntpServer, StringComparison.OrdinalIgnoreCase);

    public void ConfigureTimeSync(string ntpServer, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        state.RecordOriginal("w32time", W32TimeKind, new Dictionary<string, string?>
        {
            ["start"] = Services.StartMode("W32Time")?.ToString(),
            ["type"] = RegistryOps.ReadString(W32TimeParams, "Type"),
            ["ntpServer"] = RegistryOps.ReadString(W32TimeParams, "NtpServer"),
        });
        Services.SetStartMode(runner, "W32Time", automatic: true);
        Services.Start("W32Time");
        runner.RunChecked(ProcessRunner.SystemExe("w32tm.exe"), ["/config", "/manualpeerlist:" + ntpServer + ",0x9", "/syncfromflags:manual", "/update"]);
        var r = runner.Run(ProcessRunner.SystemExe("w32tm.exe"), ["/resync", "/force"]);
        if (!r.Ok)
        {
            log.Warn("La resynchronisation immédiate a échoué (réseau ?). Le service réessaiera automatiquement.");
        }
    }

    public void RestoreTimeSync(RollbackRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var d = record.Data;
        if (d.GetValueOrDefault("ntpServer") is { } server)
        {
            var type = d.GetValueOrDefault("type") ?? "NT5DS";
            runner.Run(ProcessRunner.SystemExe("w32tm.exe"), ["/config", "/manualpeerlist:" + server, "/syncfromflags:" + (type.Equals("NTP", StringComparison.OrdinalIgnoreCase) ? "manual" : "domhier"), "/update"]);
        }

        if (d.GetValueOrDefault("start") is "Manual" or "Disabled")
        {
            Services.SetStartMode(runner, "W32Time", automatic: false);
        }
    }

    // ---------- BitLocker (lecture seule, jamais d'activation) ----------

    /// <summary>ProtectionStatus du volume système : 0 = non protégé, 1 = protégé, 2 = inconnu ; null = indisponible.</summary>
    public static int? BitLockerProtectionStatus(string drive = "C:")
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftVolumeEncryption");
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{drive}'"));
            foreach (var o in searcher.Get())
            {
                using (o)
                {
                    return Convert.ToInt32(o["ProtectionStatus"], CultureInfo.InvariantCulture);
                }
            }
        }
        catch (ManagementException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return null;
    }

    public static string DescribeBitLocker(int? status) => status switch
    {
        1 => "BitLocker actif sur C:",
        0 => "BitLocker INACTIF sur C: (recommandé : activez-le et conservez la clé de récupération hors du PC)",
        2 => "État BitLocker inconnu (volume verrouillé ou chiffrement en cours)",
        _ => "BitLocker indisponible ou état illisible sur ce PC",
    };
}

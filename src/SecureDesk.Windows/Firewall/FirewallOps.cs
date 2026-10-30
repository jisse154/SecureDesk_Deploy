using System.Globalization;
using System.Runtime.InteropServices;
using SecureDesk.Core.Firewall;
using SecureDesk.Core.Logging;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.Firewall;

public sealed record ExistingRule(string Name, bool Enabled, int Direction, int Action, int Protocol, string LocalPorts, string RemoteAddresses, string? Grouping);

/// <summary>Pare-feu Windows via l'API COM documentée HNetCfg.FwPolicy2 (INetFwPolicy2 / INetFwRule).</summary>
public sealed class FirewallOps(ILog log, ProcessRunner runner)
{
    private const int DirectionIn = 1;
    private const int ActionBlock = 0;
    private const int ActionAllow = 1;
    private const int ProtoTcp = 6;
    private const int ProtoUdp = 17;
    private const int ProfilesAll = 0x7FFFFFFF;

    private static dynamic Policy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return Activator.CreateInstance(type)!;
    }

    public IReadOnlyList<ExistingRule> ListRules(Func<ExistingRule, bool>? filter = null)
    {
        var result = new List<ExistingRule>();
        var policy = Policy();
        try
        {
            foreach (var r in policy.Rules)
            {
                try
                {
                    var rule = new ExistingRule(
                        (string)r.Name,
                        (bool)r.Enabled,
                        (int)r.Direction,
                        (int)r.Action,
                        (int)r.Protocol,
                        (string?)r.LocalPorts ?? string.Empty,
                        (string?)r.RemoteAddresses ?? string.Empty,
                        (string?)r.Grouping);
                    if (filter is null || filter(rule))
                    {
                        result.Add(rule);
                    }
                }
                finally
                {
                    Marshal.FinalReleaseComObject(r);
                }
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }

        return result;
    }

    public IReadOnlyList<ExistingRule> OwnedRules() => ListRules(r => FirewallPlan.IsOwned(r.Name));

    /// <summary>La règle existe-t-elle exactement comme prévu (et une seule fois) ?</summary>
    public static bool IsCompliant(FirewallRule wanted, IReadOnlyList<ExistingRule> existing)
    {
        ArgumentNullException.ThrowIfNull(wanted);
        ArgumentNullException.ThrowIfNull(existing);
        var same = existing.Where(e => e.Name == wanted.Name).ToList();
        if (same.Count != 1)
        {
            return false;
        }

        var e = same[0];
        return e.Enabled
            && e.Direction == DirectionIn
            && e.Action == (wanted.Action == FwAction.Allow ? ActionAllow : ActionBlock)
            && e.Protocol == (wanted.Protocol == FwProtocol.Tcp ? ProtoTcp : ProtoUdp)
            && SamePorts(e.LocalPorts, wanted.LocalPortsText)
            && SameAddresses(e.RemoteAddresses, wanted.RemoteAddresses);
    }

    /// <summary>Remplace (supprime puis recrée) la règle : jamais de doublon.</summary>
    public void Apply(FirewallRule wanted)
    {
        ArgumentNullException.ThrowIfNull(wanted);
        Remove(wanted.Name);
        var policy = Policy();
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        dynamic rule = Activator.CreateInstance(type)!;
        try
        {
            rule.Name = wanted.Name;
            rule.Description = wanted.Description;
            rule.Grouping = FirewallPlan.Group;
            rule.Direction = DirectionIn;
            rule.Protocol = wanted.Protocol == FwProtocol.Tcp ? ProtoTcp : ProtoUdp;
            rule.LocalPorts = wanted.LocalPortsText;
            rule.RemoteAddresses = wanted.RemoteAddressesText;
            rule.Action = wanted.Action == FwAction.Allow ? ActionAllow : ActionBlock;
            rule.Profiles = ProfilesAll;
            rule.InterfaceTypes = "All";
            rule.Enabled = true;
            policy.Rules.Add(rule);
            log.Info($"Règle de pare-feu : {wanted}");
        }
        finally
        {
            Marshal.FinalReleaseComObject(rule);
            Marshal.FinalReleaseComObject(policy);
        }
    }

    /// <summary>Supprime TOUTES les règles portant ce nom (Rules.Remove n'en retire qu'une à la fois).</summary>
    public int Remove(string name)
    {
        var removed = 0;
        var policy = Policy();
        try
        {
            while (ListRules(r => r.Name == name).Count > 0 && removed < 100)
            {
                policy.Rules.Remove(name);
                removed++;
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }

        return removed;
    }

    public int RemoveAllOwned()
    {
        var count = 0;
        foreach (var name in OwnedRules().Select(r => r.Name).Distinct(StringComparer.Ordinal).ToList())
        {
            count += Remove(name);
        }

        if (count > 0)
        {
            log.Info(string.Create(CultureInfo.InvariantCulture, $"{count} règle(s) de pare-feu SecureDesk supprimée(s)."));
        }

        return count;
    }

    // ---------- Profils ----------

    private static readonly string[] ProfileKeys = ["DomainProfile", "StandardProfile", "PublicProfile"];
    private const string PolicyRoot = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    /// <summary>État effectif d'activation par profil (Domaine, Privé, Public), stratégies de groupe incluses.</summary>
    public static IReadOnlyDictionary<string, bool> ProfileStates()
    {
        var result = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var p in ProfileKeys)
        {
            var gpo = RegistryOps.ReadDword(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + p, "EnableFirewall");
            var local = RegistryOps.ReadDword(PolicyRoot + "\\" + p, "EnableFirewall");
            result[p] = (gpo ?? local ?? 1) == 1;
        }

        return result;
    }

    public void EnableAllProfiles(SecureDesk.Core.State.SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        foreach (var p in ProfileKeys)
        {
            RegistryOps.RecordOriginal(PolicyRoot + "\\" + p, "EnableFirewall", state);
        }

        runner.RunChecked(ProcessRunner.SystemExe("netsh.exe"), ["advfirewall", "set", "allprofiles", "state", "on"]);
    }

    // ---------- Comparaison ----------

    private static bool SamePorts(string actual, string wanted) =>
        Normalize(actual).SetEquals(Normalize(wanted));

    private static HashSet<string> Normalize(string list) =>
        [.. list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    /// <summary>Windows réécrit les CIDR en « réseau/masque » : on compare après normalisation.</summary>
    internal static bool SameAddresses(string actual, IReadOnlyList<string> wanted)
    {
        if (wanted.Count == 1 && wanted[0] == "*")
        {
            return actual is "*" or "";
        }

        var a = Normalize(actual).Select(NormalizeAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var w = wanted.Select(NormalizeAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return a.SetEquals(w);
    }

    internal static string NormalizeAddress(string a)
    {
        a = a.Trim();
        var slash = a.IndexOf('/', StringComparison.Ordinal);
        if (slash > 0 && a.IndexOf('.', slash) > 0)
        {
            // 10.77.0.0/255.255.255.0 → 10.77.0.0/24
            var mask = SecureDesk.Core.Net.Ipv4Cidr.ParseAddress(a[(slash + 1)..]);
            var prefix = 0;
            while (prefix < 32 && (mask & (0x8000_0000u >> prefix)) != 0)
            {
                prefix++;
            }

            return prefix == 32 ? a[..slash] : a[..slash] + "/" + prefix.ToString(CultureInfo.InvariantCulture);
        }

        return a.EndsWith("/32", StringComparison.Ordinal) ? a[..^3] : a;
    }

    /// <summary>Vrai si l'hôte existe (Windows) : utile pour éviter Registry sur une machine sans pare-feu.</summary>
    public static bool IsFirewallServiceRunning() => Services.Status("mpssvc") == System.ServiceProcess.ServiceControllerStatus.Running;
}

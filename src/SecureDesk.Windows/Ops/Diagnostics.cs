using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SecureDesk.Core.Firewall;
using SecureDesk.Core.Hardening;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Net;
using SecureDesk.Windows.Firewall;
using SecureDesk.Windows.MultiOtp;
using SecureDesk.Windows.Sys;
using SecureDesk.Windows.Tsplus;
using SecureDesk.Windows.WireGuard;

namespace SecureDesk.Windows.Ops;

/// <summary>diagnose : état complet, sans aucun secret.</summary>
public static class Diagnostics
{
    public static IReadOnlyList<CheckItem> Server(Context ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        var items = new List<CheckItem>();
        var s = ctx.State.Server;
        if (s is null)
        {
            items.Add(new("Serveur", CheckLevel.Warning, "non initialisé (init)"));
            return items;
        }

        items.AddRange(Tunnel(ctx, s.TunnelName, s.Peers.Select(p => (p.Name, p.PublicKey))));

        // Pare-feu effectif
        var fw = new FirewallOps(ctx.Log, ctx.Runner);
        var profiles = FirewallOps.ProfileStates();
        items.Add(profiles.Values.All(v => v)
            ? new("Pare-feu Windows", CheckLevel.Ok, "actif sur les 3 profils")
            : new("Pare-feu Windows", CheckLevel.Blocking, "INACTIF sur : " + string.Join(", ", profiles.Where(p => !p.Value).Select(p => p.Key))));

        var owned = fw.OwnedRules();
        var lan = ctx.Config.Server.AllowLan ? (ctx.Config.Server.LanSubnet is { } l ? Ipv4Cidr.Parse(l) : SystemInfo.DetectLan()?.Subnet) : null;
        var plan = FirewallPlan.Build(Ipv4Cidr.Parse(s.TunnelSubnet), lan, SystemInfo.RdpPort(), ctx.Config.Server.ExtraProtectedTcpPorts, s.ListenPort);
        var missing = plan.Where(r => !FirewallOps.IsCompliant(r, owned)).Select(r => r.Name).ToList();
        items.Add(missing.Count == 0
            ? new("Règles SecureDesk", CheckLevel.Ok, string.Create(CultureInfo.InvariantCulture, $"{plan.Count} règles conformes (RDP/TSplus joignables depuis le tunnel{(lan is null ? string.Empty : " et le LAN")} uniquement)"))
            : new("Règles SecureDesk", CheckLevel.Blocking, "absentes ou modifiées : " + string.Join(", ", missing) + " → relancez init"));

        var protectedPorts = new SortedSet<int>(ctx.Config.Server.ExtraProtectedTcpPorts) { SystemInfo.RdpPort() };
        var others = fw.ListRules(r => r.Enabled && r.Direction == 1 && r.Action == 1 && !FirewallPlan.IsOwned(r.Name)
                                        && (r.Protocol is 6 or 256) && TouchesPorts(r.LocalPorts, protectedPorts));
        if (others.Count > 0)
        {
            items.Add(new("Autres règles d'autorisation", CheckLevel.Warning,
                string.Create(CultureInfo.InvariantCulture, $"{others.Count} règle(s) tierce(s) ouvrent ces ports (ex. « {others[0].Name} ») ; elles sont neutralisées par SecureDesk-Block-*, qui doit rester active")));
        }

        foreach (var port in protectedPorts)
        {
            var listeners = SystemInfo.TcpListeners(port);
            if (listeners.Count > 0)
            {
                items.Add(new(string.Create(CultureInfo.InvariantCulture, $"Écoute TCP {port}"), CheckLevel.Ok,
                    string.Join(", ", listeners.Select(e => e.ToString())) + (missing.Count == 0 ? " — filtré : joignable seulement depuis les plages autorisées" : " — ATTENTION : règles incomplètes")));
            }
        }

        if (TsplusOps.Detect() is { Installed: true } ts)
        {
            items.Add(new("TSplus", CheckLevel.Ok, ts.ToString()));
            if (ctx.Config.Server.StopTsplusWebServer && TsplusOps.WebServerListening(ctx.Config.Server.ExtraProtectedTcpPorts))
            {
                items.Add(new("Serveur web TSplus", CheckLevel.Warning, "à l'écoute (redémarré ?) : il relaie aussi RDP. Bloqué hors tunnel par le pare-feu ; relancez tsplus-check pour l'arrêter."));
            }
        }
        else
        {
            items.Add(new("TSplus", CheckLevel.Warning, "non détecté"));
        }

        if (RegistryOps.ReadDword(HardeningPlan.TsPolicyPath, "UserAuthentication") != 1)
        {
            items.Add(new("NLA", CheckLevel.Warning, "stratégie NLA non imposée (lancez harden)"));
        }

        items.AddRange(TwoFactor(ctx));
        items.Add(Checks.Clock(ctx.Config.Server.NtpServer));
        items.Add(Checks.BitLocker());
        return items;
    }

    public static IReadOnlyList<CheckItem> Client(Context ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        var items = new List<CheckItem>();
        var c = ctx.State.Client;
        if (c is null)
        {
            items.Add(new("Client", CheckLevel.Warning, "non appairé (join)"));
            return items;
        }

        items.AddRange(Tunnel(ctx, c.TunnelName, [("serveur", c.ServerPublicKey)]));
        items.Add(Ping(c.ServerTunnelIp));
        items.Add(TcpProbe(c.ServerTunnelIp, c.RdpPort));
        items.Add(Checks.BitLocker(clientSide: true));
        return items;
    }

    private static IEnumerable<CheckItem> Tunnel(Context ctx, string tunnel, IEnumerable<(string Name, string PublicKey)> peers)
    {
        if (!WireGuardOps.IsInstalled)
        {
            yield return new("WireGuard", CheckLevel.Blocking, "non installé");
            yield break;
        }

        var status = WireGuardOps.TunnelStatus(tunnel);
        var inManager = WireGuardOps.ManagerHasTunnel(tunnel);
        yield return status == System.ServiceProcess.ServiceControllerStatus.Running
            ? new("Tunnel", CheckLevel.Ok, $"{tunnel} actif (démarrage {Services.StartMode(WireGuardOps.TunnelServiceName(tunnel))})")
            : new("Tunnel", CheckLevel.Warning, inManager ? $"{tunnel} inactif : activez-le depuis l'icône WireGuard" : $"{tunnel} inactif ({status?.ToString() ?? "service absent"})");

        var conf = WireGuardOps.ConfPath(tunnel);
        if (File.Exists(conf))
        {
            yield return SecureFiles.IsProtected(conf)
                ? new("ACL configuration", CheckLevel.Ok, "SYSTEM + Administrateurs uniquement")
                : new("ACL configuration", CheckLevel.Blocking, $"{conf} lisible par d'autres comptes");
        }

        if (status != System.ServiceProcess.ServiceControllerStatus.Running)
        {
            yield break;
        }

        var hs = new WireGuardOps(ctx.Log, ctx.Runner).LatestHandshakes(tunnel);
        foreach (var (name, pub) in peers)
        {
            if (hs.TryGetValue(pub, out var t) && t is { } when)
            {
                var age = DateTimeOffset.UtcNow - when;
                yield return new($"Handshake « {name} »", age < TimeSpan.FromMinutes(3) ? CheckLevel.Ok : CheckLevel.Warning,
                    string.Create(CultureInfo.InvariantCulture, $"dernier à {when.ToLocalTime():dd/MM HH:mm:ss} (il y a {(int)age.TotalSeconds} s)"));
            }
            else
            {
                yield return new($"Handshake « {name} »", CheckLevel.Warning, "aucun");
            }
        }
    }

    private static IEnumerable<CheckItem> TwoFactor(Context ctx)
    {
        var st = MultiOtpOps.Status();
        if (!st.Installed)
        {
            yield return new("multiOTP", CheckLevel.Warning, "non installé (2FA inactif)");
            yield break;
        }

        yield return new("multiOTP", st.Active ? CheckLevel.Ok : CheckLevel.Warning,
            $"{(st.Active ? "ACTIF" : "inactif")} — cpus_logon={st.CpusLogon}, cpus_unlock={st.CpusUnlock}, cpus_credui={st.CpusCredUi}; DLL {(st.DllSigned ? "signée" : "NON SIGNÉE")}");
        var enrolled = ctx.State.TwoFactor.Users.Select(u => u.Name + (u.IsAdministrator ? " (admin)" : string.Empty)).ToList();
        yield return new("Utilisateurs enrôlés", enrolled.Count > 0 ? CheckLevel.Ok : CheckLevel.Warning, enrolled.Count > 0 ? string.Join(", ", enrolled) : "aucun");
        if (ctx.State.TwoFactor.ProbationDeadlineUtc is { } d && !ctx.State.TwoFactor.Confirmed)
        {
            yield return new("Activation probatoire", CheckLevel.Warning, $"désactivation automatique à {d.ToLocalTime():HH:mm} sans confirm-2fa");
        }

        var leftovers = MultiOtpOps.LeftoverProvisioningFiles();
        yield return leftovers.Count == 0
            ? new("Fichiers QR résiduels", CheckLevel.Ok, "aucun")
            : new("Fichiers QR résiduels", CheckLevel.Blocking, string.Create(CultureInfo.InvariantCulture, $"{leftovers.Count} fichier(s) à supprimer : {string.Join(", ", leftovers.Select(Path.GetFileName))}"));
    }

    public static CheckItem Ping(string ip)
    {
        try
        {
            using var ping = new Ping();
            var reply = ping.Send(ip, 2000);
            return reply.Status == IPStatus.Success
                ? new($"Ping {ip}", CheckLevel.Ok, string.Create(CultureInfo.InvariantCulture, $"{reply.RoundtripTime} ms"))
                : new($"Ping {ip}", CheckLevel.Warning, reply.Status + " (le pare-feu du serveur peut bloquer l'ICMP ; le test RDP fait foi)");
        }
        catch (PingException ex)
        {
            return new($"Ping {ip}", CheckLevel.Warning, ex.Message);
        }
    }

    public static CheckItem TcpProbe(string ip, int port)
    {
        try
        {
            using var client = new TcpClient();
            var ok = client.ConnectAsync(ip, port).Wait(TimeSpan.FromSeconds(3));
            return ok && client.Connected
                ? new(string.Create(CultureInfo.InvariantCulture, $"RDP {ip}:{port}"), CheckLevel.Ok, "port joignable à travers le tunnel")
                : new(string.Create(CultureInfo.InvariantCulture, $"RDP {ip}:{port}"), CheckLevel.Blocking, "injoignable (tunnel inactif, pair non ajouté sur le serveur, ou RDP arrêté)");
        }
        catch (AggregateException ex) when (ex.InnerException is SocketException se)
        {
            return new(string.Create(CultureInfo.InvariantCulture, $"RDP {ip}:{port}"), CheckLevel.Blocking, se.Message);
        }
    }

    private static bool TouchesPorts(string localPorts, IReadOnlySet<int> ports)
    {
        if (localPorts is "*" or "")
        {
            return true;
        }

        foreach (var part in localPorts.Split(',', StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && ports.Contains(p))
            {
                return true;
            }

            var dash = part.Split('-');
            if (dash.Length == 2 && int.TryParse(dash[0], NumberStyles.None, CultureInfo.InvariantCulture, out var a) && int.TryParse(dash[1], NumberStyles.None, CultureInfo.InvariantCulture, out var b) && ports.Any(x => x >= a && x <= b))
            {
                return true;
            }
        }

        return false;
    }

    public static string Export(IEnumerable<string> lines, string path)
    {
        var text = string.Join(Environment.NewLine, lines.Select(Redactor.Redact));
        File.WriteAllText(path, text);
        return path;
    }
}

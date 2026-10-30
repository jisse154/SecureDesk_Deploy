using System.Globalization;
using SecureDesk.Core.Net;

namespace SecureDesk.Core.Firewall;

public enum FwProtocol
{
    Tcp,
    Udp,
}

public enum FwAction
{
    Allow,
    Block,
}

/// <summary>Règle de pare-feu entrante, indépendante de l'API Windows (testable).</summary>
public sealed record FirewallRule
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required FwAction Action { get; init; }
    public required FwProtocol Protocol { get; init; }
    public required IReadOnlyList<int> LocalPorts { get; init; }

    /// <summary>Adresses distantes au format accepté par Windows : CIDR, plage « a-b » ou adresse.</summary>
    public required IReadOnlyList<string> RemoteAddresses { get; init; }

    public string LocalPortsText => string.Join(',', LocalPorts.Order().Select(p => p.ToString(CultureInfo.InvariantCulture)));
    public string RemoteAddressesText => string.Join(',', RemoteAddresses);

    public override string ToString() =>
        $"{Name} : {(Action == FwAction.Allow ? "AUTORISER" : "BLOQUER")} {Protocol.ToString().ToUpperInvariant()} {LocalPortsText} depuis {Summarize(RemoteAddresses)}";

    private static string Summarize(IReadOnlyList<string> a) =>
        a.Count <= 3 ? string.Join(", ", a) : string.Create(CultureInfo.InvariantCulture, $"{a[0]}, … ({a.Count} plages)");
}

public static class FirewallPlan
{
    public const string Prefix = "SecureDesk-";
    public const string Group = "SecureDesk";

    /// <summary>Tout l'espace IPv6 sauf la boucle locale ::1 : RDP n'est jamais servi en IPv6 par SecureDesk.</summary>
    public const string AllIpv6 = "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

    /// <summary>Boucle locale : jamais bloquée (le serveur web TSplus relaie RDP en local).</summary>
    public static readonly Ipv4Cidr Loopback = Ipv4Cidr.Parse("127.0.0.0/8");

    /// <summary>
    /// Construit les règles entrantes.
    /// - autorisation des ports protégés depuis le tunnel (+ LAN optionnel) ;
    /// - blocage des mêmes ports depuis le complément exact (IPv4) et tout IPv6 : neutralise toute autre règle « allow »
    ///   (groupe Windows « Bureau à distance », règles posées par TSplus…), car une règle block l'emporte toujours ;
    /// - autorisation du port UDP WireGuard (seul port exposé sur Internet via la box).
    /// </summary>
    public static IReadOnlyList<FirewallRule> Build(Ipv4Cidr tunnel, Ipv4Cidr? lan, int rdpPort, IEnumerable<int> extraTcpPorts, int wireGuardPort)
    {
        ArgumentNullException.ThrowIfNull(extraTcpPorts);
        if (lan is { } l && l.Overlaps(tunnel))
        {
            throw new ArgumentException($"Le LAN {l} chevauche le tunnel {tunnel}.");
        }

        if (lan is { PrefixLength: < 8 })
        {
            throw new ArgumentException("Sous-réseau LAN trop large (préfixe < /8) : refusé par sécurité.");
        }

        var tcpPorts = new SortedSet<int>(extraTcpPorts) { rdpPort }.ToList();
        if (tcpPorts.Contains(wireGuardPort))
        {
            // Pas de conflit réel (TCP vs UDP), mais c'est presque toujours une erreur de saisie.
            throw new ArgumentException("Le port WireGuard ne doit pas être un des ports protégés.");
        }

        var allowed = new List<Ipv4Cidr> { tunnel };
        if (lan is { } lan2)
        {
            allowed.Add(lan2);
        }

        var blocked = Ipv4RangeSet.Complement(allowed.Append(Loopback)).Select(r => r.ToString()).Append(AllIpv6).ToList();
        var udpPorts = new List<int> { rdpPort }; // RDP UDP (transport UDP de RDP 8+)
        var rules = new List<FirewallRule>
        {
            new()
            {
                Name = Prefix + "Allow-TCP-Tunnel",
                Description = "SecureDesk : RDP/TSplus autorisés depuis le tunnel WireGuard uniquement.",
                Action = FwAction.Allow,
                Protocol = FwProtocol.Tcp,
                LocalPorts = tcpPorts,
                RemoteAddresses = [tunnel.ToString()],
            },
            new()
            {
                Name = Prefix + "Allow-UDP-Tunnel",
                Description = "SecureDesk : transport UDP de RDP autorisé depuis le tunnel uniquement.",
                Action = FwAction.Allow,
                Protocol = FwProtocol.Udp,
                LocalPorts = udpPorts,
                RemoteAddresses = [tunnel.ToString()],
            },
        };

        if (lan is { } lan3)
        {
            rules.Add(new()
            {
                Name = Prefix + "Allow-TCP-LAN",
                Description = "SecureDesk : RDP/TSplus autorisés depuis le réseau local (option).",
                Action = FwAction.Allow,
                Protocol = FwProtocol.Tcp,
                LocalPorts = tcpPorts,
                RemoteAddresses = [lan3.ToString()],
            });
            rules.Add(new()
            {
                Name = Prefix + "Allow-UDP-LAN",
                Description = "SecureDesk : transport UDP de RDP autorisé depuis le réseau local (option).",
                Action = FwAction.Allow,
                Protocol = FwProtocol.Udp,
                LocalPorts = udpPorts,
                RemoteAddresses = [lan3.ToString()],
            });
        }

        rules.Add(new()
        {
            Name = Prefix + "Block-TCP-Others",
            Description = "SecureDesk : RDP/TSplus bloqués depuis toute autre origine (prime sur les règles d'autorisation).",
            Action = FwAction.Block,
            Protocol = FwProtocol.Tcp,
            LocalPorts = tcpPorts,
            RemoteAddresses = blocked,
        });
        rules.Add(new()
        {
            Name = Prefix + "Block-UDP-Others",
            Description = "SecureDesk : transport UDP de RDP bloqué depuis toute autre origine.",
            Action = FwAction.Block,
            Protocol = FwProtocol.Udp,
            LocalPorts = udpPorts,
            RemoteAddresses = blocked,
        });
        rules.Add(new()
        {
            Name = Prefix + "Allow-WireGuard",
            Description = "SecureDesk : port d'écoute WireGuard (seul port à rediriger sur la box).",
            Action = FwAction.Allow,
            Protocol = FwProtocol.Udp,
            LocalPorts = [wireGuardPort],
            RemoteAddresses = ["*"],
        });
        return rules;
    }

    public static bool IsOwned(string ruleName) => ruleName?.StartsWith(Prefix, StringComparison.Ordinal) == true;
}

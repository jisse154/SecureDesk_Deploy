using SecureDesk.Core.Firewall;
using SecureDesk.Core.Net;

namespace SecureDesk.Core.Tests;

public class FirewallTests
{
    private static readonly Ipv4Cidr Tunnel = Ipv4Cidr.Parse("10.77.0.0/24");

    [Fact]
    public void Sans_lan_regles_attendues()
    {
        var rules = FirewallPlan.Build(Tunnel, null, 3389, [80, 443], 41234);
        Assert.Equal(
            ["SecureDesk-Allow-TCP-Tunnel", "SecureDesk-Allow-UDP-Tunnel", "SecureDesk-Block-TCP-Others", "SecureDesk-Block-UDP-Others", "SecureDesk-Allow-WireGuard"],
            rules.Select(r => r.Name).ToArray());
        Assert.All(rules, r => Assert.True(FirewallPlan.IsOwned(r.Name)));

        var allowTcp = rules[0];
        Assert.Equal(FwAction.Allow, allowTcp.Action);
        Assert.Equal("80,443,3389", allowTcp.LocalPortsText);
        Assert.Equal(["10.77.0.0/24"], allowTcp.RemoteAddresses);

        var wg = rules[^1];
        Assert.Equal(FwProtocol.Udp, wg.Protocol);
        Assert.Equal([41234], wg.LocalPorts);
    }

    [Fact]
    public void Le_blocage_ne_touche_ni_le_tunnel_ni_le_lan_ni_la_boucle_locale()
    {
        var lan = Ipv4Cidr.Parse("192.168.1.0/24");
        var rules = FirewallPlan.Build(Tunnel, lan, 3389, [80, 443], 41234);
        var block = rules.Single(r => r.Name == "SecureDesk-Block-TCP-Others");
        Assert.Equal(FwAction.Block, block.Action);
        Assert.Contains(FirewallPlan.AllIpv6, block.RemoteAddresses);

        var ranges = block.RemoteAddresses.Where(a => a != FirewallPlan.AllIpv6)
            .Select(a => a.Split('-'))
            .Select(p => (Start: Ipv4Cidr.ParseAddress(p[0]), End: Ipv4Cidr.ParseAddress(p.Length > 1 ? p[1] : p[0])))
            .ToList();

        bool Blocked(string ip) => ranges.Any(r => Ipv4Cidr.ParseAddress(ip) >= r.Start && Ipv4Cidr.ParseAddress(ip) <= r.End);

        Assert.False(Blocked("10.77.0.2"));
        Assert.False(Blocked("10.77.0.254"));
        Assert.False(Blocked("192.168.1.50"));
        Assert.False(Blocked("127.0.0.1"));
        Assert.True(Blocked("10.77.1.1"));
        Assert.True(Blocked("192.168.2.1"));
        Assert.True(Blocked("8.8.8.8"));
        Assert.True(Blocked("82.64.10.20"));
        Assert.True(Blocked("0.0.0.0"));
        Assert.True(Blocked("255.255.255.255"));
        Assert.Contains(rules, r => r.Name == "SecureDesk-Allow-TCP-LAN" && r.RemoteAddresses.SequenceEqual(["192.168.1.0/24"]));
    }

    [Fact]
    public void Ipv6_bloque_sauf_boucle_locale()
    {
        Assert.StartsWith("::2-", FirewallPlan.AllIpv6, StringComparison.Ordinal);
    }

    [Fact]
    public void Lan_qui_chevauche_le_tunnel_refuse()
    {
        Assert.Throws<ArgumentException>(() => FirewallPlan.Build(Tunnel, Ipv4Cidr.Parse("10.0.0.0/8"), 3389, [], 41234));
        Assert.Throws<ArgumentException>(() => FirewallPlan.Build(Tunnel, Ipv4Cidr.Parse("0.0.0.0/0"), 3389, [], 41234));
    }

    [Fact]
    public void Port_wireguard_egal_a_un_port_protege_refuse()
    {
        Assert.Throws<ArgumentException>(() => FirewallPlan.Build(Tunnel, null, 3389, [443], 443));
    }

    [Fact]
    public void Port_rdp_personnalise_et_doublons()
    {
        var rules = FirewallPlan.Build(Tunnel, null, 3390, [443, 443, 3390], 41234);
        Assert.Equal("443,3390", rules[0].LocalPortsText);
        Assert.Equal([3390], rules[1].LocalPorts);
    }

    [Fact]
    public void Build_est_deterministe()
    {
        var a = FirewallPlan.Build(Tunnel, null, 3389, [80, 443], 41234);
        var b = FirewallPlan.Build(Tunnel, null, 3389, [443, 80], 41234);
        Assert.Equal(a.Select(r => r.ToString()), b.Select(r => r.ToString()));
        Assert.Equal(a.Select(r => r.RemoteAddressesText), b.Select(r => r.RemoteAddressesText));
    }
}

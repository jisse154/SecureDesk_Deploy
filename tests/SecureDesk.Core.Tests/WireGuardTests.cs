using SecureDesk.Core.Net;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.Security;
using SecureDesk.Core.WireGuard;

namespace SecureDesk.Core.Tests;

public class WireGuardTests
{
    private static readonly FakeKeyGenerator Keys = new();
    private static readonly Ipv4Cidr Subnet = Ipv4Cidr.Parse("10.77.0.0/24");

    private static ServerInvitation Invitation(WgPublicKey serverPub, WgSecretKey psk) => new()
    {
        InvitationId = "inv-1",
        PeerName = "pc-perso",
        ServerPublicKey = serverPub,
        EndpointHost = "bureau.ddns.net",
        EndpointPort = 41234,
        ServerTunnelIp = "10.77.0.1",
        ClientTunnelIp = "10.77.0.2",
        TunnelSubnet = "10.77.0.0/24",
        RdpPort = 3389,
        PresharedKey = psk,
        CreatedUtc = DateTimeOffset.UnixEpoch,
        ExpiresUtc = DateTimeOffset.MaxValue,
    };

    [Fact]
    public void Config_client_split_tunnel_et_keepalive()
    {
        var server = Keys.GenerateKeyPair();
        var client = Keys.GenerateKeyPair();
        var psk = Keys.GeneratePresharedKey();
        var text = TunnelConfigs.Client(client.PrivateKey, Invitation(server.PublicKey, psk)).Render();

        Assert.Contains("Address = 10.77.0.2/32", text, StringComparison.Ordinal);
        Assert.Contains("AllowedIPs = 10.77.0.1/32", text, StringComparison.Ordinal);
        Assert.Contains("PersistentKeepalive = 25", text, StringComparison.Ordinal);
        Assert.Contains("Endpoint = bureau.ddns.net:41234", text, StringComparison.Ordinal);
        Assert.Contains("PublicKey = " + server.PublicKey.Value, text, StringComparison.Ordinal);
        Assert.Contains("PresharedKey = " + psk.Reveal(), text, StringComparison.Ordinal);
        Assert.DoesNotContain("0.0.0.0/0", text, StringComparison.Ordinal);
        Assert.DoesNotContain("DNS", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ListenPort", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Config_serveur_un_pair_par_ip()
    {
        var server = Keys.GenerateKeyPair();
        var p1 = new ServerPeer("pc-perso", Keys.GenerateKeyPair().PublicKey, Keys.GeneratePresharedKey(), "10.77.0.2");
        var p2 = new ServerPeer("portable", Keys.GenerateKeyPair().PublicKey, Keys.GeneratePresharedKey(), "10.77.0.3");
        var cfg = TunnelConfigs.Server(server.PrivateKey, Subnet, 41234, [p1, p2]);
        var text = cfg.Render();

        Assert.Contains("Address = 10.77.0.1/24", text, StringComparison.Ordinal);
        Assert.Contains("ListenPort = 41234", text, StringComparison.Ordinal);
        Assert.Contains("AllowedIPs = 10.77.0.2/32", text, StringComparison.Ordinal);
        Assert.Contains("AllowedIPs = 10.77.0.3/32", text, StringComparison.Ordinal);
        Assert.Equal(2, text.Split("[Peer]").Length - 1);
        Assert.DoesNotContain("Endpoint", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Config_serveur_refuse_conflits()
    {
        var server = Keys.GenerateKeyPair();
        var pub = Keys.GenerateKeyPair().PublicKey;
        Assert.Throws<ArgumentException>(() => TunnelConfigs.Server(server.PrivateKey, Subnet, 1, [
            new("a", pub, Keys.GeneratePresharedKey(), "10.77.0.2"),
            new("b", Keys.GenerateKeyPair().PublicKey, Keys.GeneratePresharedKey(), "10.77.0.2")]));
        Assert.Throws<ArgumentException>(() => TunnelConfigs.Server(server.PrivateKey, Subnet, 1, [
            new("a", pub, Keys.GeneratePresharedKey(), "10.77.0.2"),
            new("b", pub, Keys.GeneratePresharedKey(), "10.77.0.3")]));
        Assert.Throws<ArgumentException>(() => TunnelConfigs.Server(server.PrivateKey, Subnet, 1, [
            new("a", pub, Keys.GeneratePresharedKey(), "10.77.0.1")]));
        Assert.Throws<ArgumentException>(() => TunnelConfigs.Server(server.PrivateKey, Subnet, 1, [
            new("a", pub, Keys.GeneratePresharedKey(), "10.78.0.2")]));
    }

    [Fact]
    public void Aller_retour_render_parse()
    {
        var server = Keys.GenerateKeyPair();
        var peer = new ServerPeer("pc-perso", Keys.GenerateKeyPair().PublicKey, Keys.GeneratePresharedKey(), "10.77.0.2");
        var cfg = TunnelConfigs.Server(server.PrivateKey, Subnet, 41234, [peer]);
        var parsed = WgConfig.Parse(cfg.Render());

        Assert.Equal(server.PrivateKey, parsed.Interface.PrivateKey);
        Assert.Equal(41234, parsed.Interface.ListenPort);
        Assert.Equal(["10.77.0.1/24"], parsed.Interface.Addresses);
        var p = Assert.Single(parsed.Peers);
        Assert.Equal("pc-perso", p.Name);
        Assert.Equal(peer.PublicKey, p.PublicKey);
        Assert.Equal(peer.PresharedKey, p.PresharedKey);
        Assert.Equal(["10.77.0.2/32"], p.AllowedIps);
        Assert.Equal(cfg.Render(), parsed.Render());
    }

    [Fact]
    public void Prochaine_ip_libre()
    {
        Assert.Equal("10.77.0.2", TunnelConfigs.NextFreeIp(Subnet, []));
        Assert.Equal("10.77.0.4", TunnelConfigs.NextFreeIp(Subnet, ["10.77.0.2", "10.77.0.3"]));
        Assert.Equal("10.77.0.3", TunnelConfigs.NextFreeIp(Subnet, ["10.77.0.2", "10.77.0.4"]));
        var full = Enumerable.Range(2, 253).Select(i => "10.77.0." + i).ToList();
        Assert.Throws<InvalidOperationException>(() => TunnelConfigs.NextFreeIp(Subnet, full));
    }

    [Fact]
    public void Les_secrets_ne_fuient_pas_par_ToString()
    {
        var kp = Keys.GenerateKeyPair();
        Assert.DoesNotContain(kp.PrivateKey.Reveal(), kp.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(kp.PrivateKey.Reveal(), $"{kp.PrivateKey}", StringComparison.Ordinal);
        var cfg = TunnelConfigs.Server(kp.PrivateKey, Subnet, 1, []);
        Assert.DoesNotContain(kp.PrivateKey.Reveal(), cfg.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")]
    public void Cles_invalides_refusees(string key)
    {
        Assert.False(WgKeyFormat.IsValid(key));
        Assert.Throws<FormatException>(() => new WgPublicKey(key));
    }

    [Fact]
    public void Empreinte_stable_et_courte()
    {
        var pub = new WgPublicKey("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
        Assert.Matches("^[0-9A-F]{4}(-[0-9A-F]{4}){3}$", pub.Fingerprint);
        Assert.Equal(pub.Fingerprint, new WgPublicKey(pub.Value).Fingerprint);
    }
}

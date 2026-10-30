using SecureDesk.Core.Cli;
using SecureDesk.Core.Config;

namespace SecureDesk.Core.Tests;

public class CommandLineTests
{
    [Fact]
    public void Sans_argument_assistant()
    {
        Assert.Equal("wizard", CommandLine.Parse([]).Verb);
    }

    [Fact]
    public void Verbe_argument_options()
    {
        var cl = CommandLine.Parse(["add-peer", @"E:\pairing-client.sdpair", "--dry-run", "--config=c.json", "--verbose"]);
        Assert.Equal("add-peer", cl.Verb);
        Assert.Equal(@"E:\pairing-client.sdpair", cl.Argument);
        Assert.True(cl.DryRun);
        Assert.True(cl.Has("verbose"));
        Assert.Equal("c.json", cl.Get("config"));
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("init", "--unknown")]
    [InlineData("init", "--out")]
    [InlineData("init", "--dry-run=1")]
    [InlineData("join", "a", "b")]
    [InlineData("init", "--port", "1", "--port", "2")]
    public void Erreurs_explicites(params string[] args)
    {
        Assert.Throws<CommandLineException>(() => CommandLine.Parse(args));
    }

    [Fact]
    public void Aide()
    {
        Assert.Equal("help", CommandLine.Parse(["--help"]).Verb);
        Assert.Equal("help", CommandLine.Parse(["/?"]).Verb);
        var usage = CommandLine.Usage();
        foreach (var (verb, _, _) in CommandLine.Verbs)
        {
            Assert.Contains(verb, usage, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Les_commandes_exigees_existent()
    {
        foreach (var v in new[] { "init", "join", "add-peer", "rotate-keys", "revoke-peer", "enroll-user", "disable-2fa", "diagnose", "uninstall" })
        {
            Assert.Contains(CommandLine.Verbs, x => x.Verb == v);
        }
    }

    [Fact]
    public void Surcharges_de_configuration()
    {
        var cl = CommandLine.Parse(["init", "--endpoint", "x.ddns.net", "--port", "41000", "--users", "alice, bob", "--lan-subnet", "192.168.1.0/24", "--scope", "all", "--auto-start", "--wireguard-msi", "wg.msi"]);
        var c = ConfigOverrides.Apply(new SecureDeskConfig(), cl);
        Assert.Equal("x.ddns.net", c.Server.EndpointHost);
        Assert.Equal(41000, c.Server.ListenPort);
        Assert.Equal(["alice", "bob"], c.Server.Users.Select(u => u.Name));
        Assert.True(c.Server.AllowLan);
        Assert.Equal("192.168.1.0/24", c.Server.LanSubnet);
        Assert.Equal(TwoFactorScope.RemoteAndLocal, c.Server.TwoFactor.Scope);
        Assert.True(c.Client.AutoStartTunnel);
        Assert.Equal("wg.msi", c.Installers.WireGuardMsi);
    }

    [Fact]
    public void Surcharges_invalides()
    {
        Assert.Throws<CommandLineException>(() => ConfigOverrides.Apply(new SecureDeskConfig(), CommandLine.Parse(["enable-2fa", "--scope", "partout"])));
        Assert.Throws<CommandLineException>(() => ConfigOverrides.Apply(new SecureDeskConfig(), CommandLine.Parse(["join", "f", "--auto-start", "--manual-start"])));
        Assert.Throws<CommandLineException>(() => ConfigOverrides.Apply(new SecureDeskConfig(), CommandLine.Parse(["init", "--port", "abc"])));
    }
}

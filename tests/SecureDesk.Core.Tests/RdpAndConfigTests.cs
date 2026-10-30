using SecureDesk.Core.Config;
using SecureDesk.Core.Rdp;

namespace SecureDesk.Core.Tests;

public class RdpAndConfigTests
{
    [Fact]
    public void Fichier_rdp_sans_mot_de_passe_et_sans_redirection_par_defaut()
    {
        var rdp = RdpFile.Build("10.77.0.1", 3389, new RedirectionOptions(), "alice");
        Assert.Contains("full address:s:10.77.0.1\r\n", rdp, StringComparison.Ordinal);
        Assert.Contains("enablecredsspsupport:i:1", rdp, StringComparison.Ordinal);
        Assert.Contains("redirectclipboard:i:0", rdp, StringComparison.Ordinal);
        Assert.Contains("redirectprinters:i:0", rdp, StringComparison.Ordinal);
        Assert.Contains("redirectdrives:i:0", rdp, StringComparison.Ordinal);
        Assert.Contains("drivestoredirect:s:\r\n", rdp, StringComparison.Ordinal);
        Assert.Contains("username:s:alice", rdp, StringComparison.Ordinal);
        Assert.DoesNotContain("password", rdp, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Fichier_rdp_port_et_redirections()
    {
        var rdp = RdpFile.Build("10.77.0.1", 3390, new RedirectionOptions { Clipboard = true, Drives = true }, null);
        Assert.Contains("full address:s:10.77.0.1:3390", rdp, StringComparison.Ordinal);
        Assert.Contains("redirectclipboard:i:1", rdp, StringComparison.Ordinal);
        Assert.Contains("drivestoredirect:s:*", rdp, StringComparison.Ordinal);
        Assert.DoesNotContain("username", rdp, StringComparison.Ordinal);
    }

    private static SecureDeskConfig ValidConfig() => new()
    {
        Server = new ServerOptions
        {
            EndpointHost = "bureau.ddns.net",
            ListenPort = 41234,
            Users = [new UserSpec { Name = "alice" }, new UserSpec { Name = "bob" }],
        },
    };

    [Fact]
    public void Configuration_par_defaut_valide()
    {
        Assert.Empty(ValidConfig().ValidateServer());
    }

    [Fact]
    public void Erreurs_de_configuration_detectees()
    {
        var c = ValidConfig();
        c.Server.EndpointHost = "";
        c.Server.ListenPort = 70000;
        c.Server.TunnelSubnet = "10.77.0.1/24";
        c.Server.Users.Add(new UserSpec { Name = "ALICE" });
        c.Server.Users.Add(new UserSpec { Name = "bad/name" });
        c.Server.PasswordPolicy.MinLength = 20;
        c.Server.TunnelName = "nom avec espaces";
        var errors = c.ValidateServer();
        Assert.True(errors.Count >= 7, string.Join("\n", errors));
    }

    [Fact]
    public void Lan_chevauchant_le_tunnel_refuse()
    {
        var c = ValidConfig();
        c.Server.AllowLan = true;
        c.Server.LanSubnet = "10.77.0.0/16";
        Assert.Contains(c.ValidateServer(), e => e.Contains("chevauche", StringComparison.Ordinal));
    }

    [Fact]
    public void Json_aller_retour_et_champ_inconnu_refuse()
    {
        var c = ValidConfig();
        c.Server.TwoFactor.Scope = TwoFactorScope.RemoteAndLocal;
        var json = c.ToJson();
        Assert.Contains("\"remoteAndLocal\"", json, StringComparison.OrdinalIgnoreCase);
        var back = SecureDeskConfig.FromJson(json);
        Assert.Equal(TwoFactorScope.RemoteAndLocal, back.Server.TwoFactor.Scope);
        Assert.Equal(["alice", "bob"], back.Server.Users.Select(u => u.Name));
        Assert.ThrowsAny<System.Text.Json.JsonException>(() => SecureDeskConfig.FromJson("{\"server\":{\"password\":\"x\"}}"));
    }

    [Fact]
    public void Comptes_2fa_par_defaut_les_utilisateurs()
    {
        var c = ValidConfig();
        Assert.Equal(["alice", "bob"], c.TwoFactorAccounts());
        c.Server.TwoFactor.Accounts = ["admin"];
        Assert.Equal(["admin"], c.TwoFactorAccounts());
    }

    [Fact]
    public void Exemple_de_configuration_du_depot_valide()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "securedesk.example.json");
        var c = SecureDeskConfig.Load(path);
        Assert.Empty(c.ValidateServer());
    }
}

public class InstallerManifestTests
{
    [Fact]
    public void Manifeste_embarque_lu_correctement()
    {
        var m = SecureDesk.Core.Installers.InstallerManifest.Embedded();
        Assert.Equal("WireGuard LLC", m.WireGuard.SignerSubjectContains);
        Assert.True(m.WireGuard.RequireAuthenticode);
        Assert.Contains("multiOTP", m.MultiOtp.DisplayName, StringComparison.Ordinal);
        Assert.Contains("SysCo", m.MultiOtp.SignerSubjectContains, StringComparison.Ordinal);
        Assert.StartsWith("https://", m.VcRedist.Url, StringComparison.Ordinal);
    }

    [Fact]
    public void Manifeste_insensible_a_la_casse_des_cles()
    {
        var m = SecureDesk.Core.Installers.InstallerManifest.FromJson("{\"wireguard\":{\"sha256\":\"AB\"},\"MULTIOTP\":{\"version\":\"5\"}}");
        Assert.Equal("AB", m.WireGuard.Sha256);
        Assert.Equal("5", m.MultiOtp.Version);
    }
}

using System.Text.Json.Nodes;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.Security;

namespace SecureDesk.Core.Tests;

public class PairingTests
{
    private const int FastIterations = PairingFile.MinIterations;
    private static readonly SensitiveText Pass = new("correct-horse-battery-staple");
    private static readonly FakeKeyGenerator Keys = new();

    private static ServerInvitation NewInvitation(WgSecretKey? psk = null, DateTimeOffset? expires = null) => new()
    {
        InvitationId = "6f1c2a",
        PeerName = "pc-perso",
        ServerPublicKey = Keys.GenerateKeyPair().PublicKey,
        EndpointHost = "bureau.ddns.net",
        EndpointPort = 41234,
        ServerTunnelIp = "10.77.0.1",
        ClientTunnelIp = "10.77.0.2",
        TunnelSubnet = "10.77.0.0/24",
        RdpPort = 3389,
        PresharedKey = psk ?? Keys.GeneratePresharedKey(),
        CreatedUtc = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero),
        ExpiresUtc = expires ?? new DateTimeOffset(2026, 11, 6, 12, 0, 0, TimeSpan.Zero),
    };

    private static readonly FixedClock Clock = new(new DateTimeOffset(2026, 10, 31, 0, 0, 0, TimeSpan.Zero));

    [Fact]
    public void Fichier_serveur_aller_retour()
    {
        var inv = NewInvitation();
        var json = PairingFile.WriteServer(inv, Pass, FastIterations);
        var back = PairingFile.ReadServer(json, Pass, Clock);
        Assert.Equal(inv.InvitationId, back.InvitationId);
        Assert.Equal(inv.ServerPublicKey, back.ServerPublicKey);
        Assert.Equal(inv.PresharedKey, back.PresharedKey);
        Assert.Equal(inv.EndpointHost, back.EndpointHost);
        Assert.Equal(inv.EndpointPort, back.EndpointPort);
        Assert.Equal(inv.ClientTunnelIp, back.ClientTunnelIp);
        Assert.Equal(inv.ExpiresUtc, back.ExpiresUtc);
    }

    [Fact]
    public void Fichier_serveur_ne_contient_aucun_secret_en_clair()
    {
        var inv = NewInvitation();
        var json = PairingFile.WriteServer(inv, Pass, FastIterations);
        Assert.DoesNotContain(inv.PresharedKey.Reveal(), json, StringComparison.Ordinal);
        Assert.DoesNotContain(inv.ServerPublicKey.Value, json, StringComparison.Ordinal);
        Assert.DoesNotContain("bureau.ddns.net", json, StringComparison.Ordinal);
        Assert.DoesNotContain(Pass.Reveal(), json, StringComparison.Ordinal);
        Assert.Contains("\"kind\": \"server\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Mauvaise_phrase_de_passe_refusee()
    {
        var json = PairingFile.WriteServer(NewInvitation(), Pass, FastIterations);
        var ex = Assert.Throws<PairingException>(() => PairingFile.ReadServer(json, new SensitiveText("wrong-passphrase-123"), Clock));
        Assert.Contains("Phrase de passe incorrecte", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ciphertext")]
    [InlineData("nonce")]
    [InlineData("tag")]
    public void Alteration_detectee(string field)
    {
        var json = PairingFile.WriteServer(NewInvitation(), Pass, FastIterations);
        var node = JsonNode.Parse(json)!;
        var bytes = Convert.FromBase64String(node[field]!.GetValue<string>());
        bytes[0] ^= 0x01;
        node[field] = Convert.ToBase64String(bytes);
        Assert.Throws<PairingException>(() => PairingFile.ReadServer(node.ToJsonString(), Pass, Clock));
    }

    [Fact]
    public void Alteration_de_l_en_tete_detectee_par_AAD()
    {
        var json = PairingFile.WriteServer(NewInvitation(), Pass, FastIterations);
        var node = JsonNode.Parse(json)!;
        // Abaisser le nombre d'itérations (attaque par dégradation) invalide l'authentification.
        node["kdf"]!["iterations"] = FastIterations + 1;
        Assert.Throws<PairingException>(() => PairingFile.ReadServer(node.ToJsonString(), Pass, Clock));
    }

    [Fact]
    public void Iterations_trop_faibles_refusees()
    {
        var json = PairingFile.WriteServer(NewInvitation(), Pass, FastIterations);
        var node = JsonNode.Parse(json)!;
        node["kdf"]!["iterations"] = 1000;
        var ex = Assert.Throws<PairingException>(() => PairingFile.ReadServer(node.ToJsonString(), Pass, Clock));
        Assert.Contains("non acceptés", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Invitation_expiree_refusee()
    {
        var inv = NewInvitation(expires: new DateTimeOffset(2026, 10, 30, 13, 0, 0, TimeSpan.Zero));
        var json = PairingFile.WriteServer(inv, Pass, FastIterations);
        var ex = Assert.Throws<PairingException>(() => PairingFile.ReadServer(json, Pass, Clock));
        Assert.Contains("expiré", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Phrase_de_passe_faible_refusee()
    {
        Assert.Throws<PairingException>(() => PairingFile.WriteServer(NewInvitation(), new SensitiveText("court"), FastIterations));
        Assert.Throws<PairingException>(() => PairingFile.WriteServer(NewInvitation(), new SensitiveText("aaaaaaaaaaaaaaaaaaaa"), FastIterations));
    }

    [Fact]
    public void Phrase_generee_conforme()
    {
        for (var i = 0; i < 50; i++)
        {
            var p = PassphrasePolicy.Generate();
            Assert.Empty(PassphrasePolicy.Check(p));
            Assert.Matches("^[A-Z2-9]{4}(-[A-Z2-9]{4}){5}$", p.Reveal());
        }
    }

    [Fact]
    public void Fichier_client_aller_retour_et_sans_secret()
    {
        var psk = Keys.GeneratePresharedKey();
        var client = Keys.GenerateKeyPair();
        var resp = new ClientResponse
        {
            InvitationId = "6f1c2a",
            PeerName = "pc-perso",
            ClientPublicKey = client.PublicKey,
            ClientTunnelIp = "10.77.0.2",
            CreatedUtc = DateTimeOffset.UnixEpoch,
        };
        var json = PairingFile.WriteClient(resp, psk);
        Assert.DoesNotContain(psk.Reveal(), json, StringComparison.Ordinal);
        Assert.DoesNotContain(client.PrivateKey.Reveal(), json, StringComparison.Ordinal);
        Assert.Equal("6f1c2a", PairingFile.PeekClientInvitationId(json));
        var back = PairingFile.ReadClient(json, psk);
        Assert.Equal(client.PublicKey, back.ClientPublicKey);
        Assert.Equal("10.77.0.2", back.ClientTunnelIp);
    }

    [Fact]
    public void Fichier_client_falsifie_ou_autre_psk_refuse()
    {
        var psk = Keys.GeneratePresharedKey();
        var resp = new ClientResponse
        {
            InvitationId = "6f1c2a",
            PeerName = "pc-perso",
            ClientPublicKey = Keys.GenerateKeyPair().PublicKey,
            ClientTunnelIp = "10.77.0.2",
            CreatedUtc = DateTimeOffset.UnixEpoch,
        };
        var json = PairingFile.WriteClient(resp, psk);
        Assert.Throws<PairingException>(() => PairingFile.ReadClient(json, Keys.GeneratePresharedKey()));

        var node = JsonNode.Parse(json)!;
        node["payload"]!["clientPublicKey"] = FakeKeyGenerator.RandomKey();
        Assert.Throws<PairingException>(() => PairingFile.ReadClient(node.ToJsonString(), psk));

        node = JsonNode.Parse(json)!;
        node["payload"]!["clientTunnelIp"] = "10.77.0.9";
        Assert.Throws<PairingException>(() => PairingFile.ReadClient(node.ToJsonString(), psk));
    }

    [Fact]
    public void Inversion_des_fichiers_expliquee()
    {
        var psk = Keys.GeneratePresharedKey();
        var serverJson = PairingFile.WriteServer(NewInvitation(psk), Pass, FastIterations);
        var ex = Assert.Throws<PairingException>(() => PairingFile.ReadClient(serverJson, psk));
        Assert.Contains("SERVEUR", ex.Message, StringComparison.Ordinal);
        Assert.Throws<PairingException>(() => PairingFile.ReadServer("{\"format\":\"autre\"}", Pass, Clock));
        Assert.Throws<PairingException>(() => PairingFile.ReadServer("pas du json", Pass, Clock));
    }
}

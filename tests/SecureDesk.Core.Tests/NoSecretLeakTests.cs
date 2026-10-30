using SecureDesk.Core.Logging;
using SecureDesk.Core.Net;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.Security;
using SecureDesk.Core.State;
using SecureDesk.Core.WireGuard;

namespace SecureDesk.Core.Tests;

/// <summary>Critère d'acceptation : aucune clé privée, graine TOTP ou QR n'apparaît dans un log, un rapport ou un fichier d'appairage.</summary>
public class NoSecretLeakTests
{
    [Fact]
    public void Parcours_complet_sans_fuite()
    {
        var keys = new FakeKeyGenerator();
        var server = keys.GenerateKeyPair();
        var client = keys.GenerateKeyPair();
        var psk = keys.GeneratePresharedKey();
        const string seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        var otpUri = $"otpauth://totp/multiOTP:alice?secret={seed}&issuer=multiOTP";
        var secrets = new[] { server.PrivateKey.Reveal(), client.PrivateKey.Reveal(), psk.Reveal(), seed };

        var log = new MemoryLog();
        var subnet = Ipv4Cidr.Parse("10.77.0.0/24");
        var serverConf = TunnelConfigs.Server(server.PrivateKey, subnet, 41234, [new ServerPeer("pc", client.PublicKey, psk, "10.77.0.2")]);
        // Un développeur distrait journalise des objets et même le texte de configuration : tout doit être masqué.
        log.Info($"Clé {server.PrivateKey} psk {psk} config {serverConf}");
        log.Info(serverConf.Render());
        log.Info("Provisionnement : " + otpUri);
        log.Info("seed " + seed);

        var invitation = new ServerInvitation
        {
            InvitationId = "abc",
            PeerName = "pc",
            ServerPublicKey = server.PublicKey,
            EndpointHost = "x.ddns.net",
            EndpointPort = 41234,
            ServerTunnelIp = "10.77.0.1",
            ClientTunnelIp = "10.77.0.2",
            TunnelSubnet = "10.77.0.0/24",
            RdpPort = 3389,
            PresharedKey = psk,
            CreatedUtc = DateTimeOffset.UtcNow,
            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1),
        };
        log.Info(invitation.ToString());
        var serverFile = PairingFile.WriteServer(invitation, new SensitiveText("phrase-de-passe-longue"), PairingFile.MinIterations);
        var clientFile = PairingFile.WriteClient(new ClientResponse
        {
            InvitationId = "abc",
            PeerName = "pc",
            ClientPublicKey = client.PublicKey,
            ClientTunnelIp = "10.77.0.2",
            CreatedUtc = DateTimeOffset.UtcNow,
        }, psk);

        var state = new SecureDeskState { Role = "server", Server = new ServerState { ServerPublicKey = server.PublicKey.Value } };
        var stateJson = state.ToJson();

        foreach (var secret in secrets)
        {
            Assert.DoesNotContain(secret, log.AllText(), StringComparison.Ordinal);
            Assert.DoesNotContain(secret, serverFile, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, clientFile, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, stateJson, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("otpauth", log.AllText(), StringComparison.OrdinalIgnoreCase);
    }
}

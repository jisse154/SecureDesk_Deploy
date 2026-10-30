using System.Globalization;
using SecureDesk.Core.Net;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.Security;

namespace SecureDesk.Core.WireGuard;

public sealed record ServerPeer(string Name, WgPublicKey PublicKey, WgSecretKey PresharedKey, string TunnelIp);

public static class TunnelConfigs
{
    public const int Keepalive = 25;

    /// <summary>Adresse du serveur dans le tunnel : premier hôte du sous-réseau (ex. 10.77.0.1).</summary>
    public static string ServerIp(Ipv4Cidr subnet) => Ipv4Cidr.FormatAddress(subnet.Host(1));

    public static WgConfig Server(WgSecretKey privateKey, Ipv4Cidr subnet, int listenPort, IEnumerable<ServerPeer> peers)
    {
        ArgumentNullException.ThrowIfNull(peers);
        var list = peers.ToList();
        var seenIps = new HashSet<string>(StringComparer.Ordinal);
        var seenKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in list)
        {
            if (!subnet.Contains(p.TunnelIp))
            {
                throw new ArgumentException($"L'IP {p.TunnelIp} du pair « {p.Name} » est hors du sous-réseau {subnet}.");
            }

            if (p.TunnelIp == ServerIp(subnet) || !seenIps.Add(p.TunnelIp))
            {
                throw new ArgumentException($"IP de tunnel en conflit : {p.TunnelIp}.");
            }

            if (!seenKeys.Add(p.PublicKey.Value))
            {
                throw new ArgumentException($"Clé publique en double (pair « {p.Name} »).");
            }
        }

        return new WgConfig
        {
            Interface = new WgInterface
            {
                PrivateKey = privateKey,
                Addresses = [string.Create(CultureInfo.InvariantCulture, $"{ServerIp(subnet)}/{subnet.PrefixLength}")],
                ListenPort = listenPort,
            },
            Peers = [.. list.Select(p => new WgPeer
            {
                Name = p.Name,
                PublicKey = p.PublicKey,
                PresharedKey = p.PresharedKey,
                AllowedIps = [p.TunnelIp + "/32"],
            })],
        };
    }

    /// <summary>
    /// Configuration client : split tunnel strict (AllowedIPs = IP du serveur /32),
    /// PersistentKeepalive = 25, pas de DNS ni de route par défaut.
    /// </summary>
    public static WgConfig Client(WgSecretKey privateKey, ServerInvitation invitation)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        return new WgConfig
        {
            Interface = new WgInterface
            {
                PrivateKey = privateKey,
                Addresses = [invitation.ClientTunnelIp + "/32"],
            },
            Peers =
            [
                new WgPeer
                {
                    Name = "serveur",
                    PublicKey = invitation.ServerPublicKey,
                    PresharedKey = invitation.PresharedKey,
                    AllowedIps = [invitation.ServerTunnelIp + "/32"],
                    Endpoint = Endpoint.Format(invitation.EndpointHost, invitation.EndpointPort),
                    PersistentKeepalive = Keepalive,
                },
            ],
        };
    }

    /// <summary>Prochaine IP libre (à partir du 2e hôte : le 1er est le serveur).</summary>
    public static string NextFreeIp(Ipv4Cidr subnet, IEnumerable<string> used)
    {
        var taken = new HashSet<string>(used, StringComparer.Ordinal) { ServerIp(subnet) };
        var max = (int)Math.Min(subnet.Size - 2, int.MaxValue);
        for (var i = 2; i <= max; i++)
        {
            var ip = Ipv4Cidr.FormatAddress(subnet.Host(i));
            if (!taken.Contains(ip))
            {
                return ip;
            }
        }

        throw new InvalidOperationException($"Plus aucune adresse libre dans {subnet}.");
    }
}

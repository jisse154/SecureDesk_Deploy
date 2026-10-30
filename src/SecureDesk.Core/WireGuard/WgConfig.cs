using System.Globalization;
using System.Text;
using SecureDesk.Core.Security;

namespace SecureDesk.Core.WireGuard;

public sealed record WgPeer
{
    public required string Name { get; init; }
    public required WgPublicKey PublicKey { get; init; }
    public WgSecretKey? PresharedKey { get; init; }
    public required IReadOnlyList<string> AllowedIps { get; init; }
    public string? Endpoint { get; init; }
    public int? PersistentKeepalive { get; init; }
}

public sealed record WgInterface
{
    public required WgSecretKey PrivateKey { get; init; }
    public required IReadOnlyList<string> Addresses { get; init; }
    public int? ListenPort { get; init; }
}

/// <summary>Configuration WireGuard au format wg-quick (lu par wireguard.exe /installtunnelservice).</summary>
public sealed record WgConfig
{
    public required WgInterface Interface { get; init; }
    public IReadOnlyList<WgPeer> Peers { get; init; } = [];

    public const string PeerNameComment = "# SecureDesk-Peer = ";

    /// <summary>Rendu texte. Le résultat contient la clé privée : à n'écrire que dans un fichier protégé par ACL.</summary>
    public string Render()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Généré par SecureDesk. Ne pas modifier à la main : utilisez SecureDesk.exe.");
        sb.AppendLine("[Interface]");
        sb.Append("PrivateKey = ").AppendLine(Interface.PrivateKey.Reveal());
        sb.Append("Address = ").AppendLine(string.Join(", ", Interface.Addresses));
        if (Interface.ListenPort is { } port)
        {
            sb.Append("ListenPort = ").AppendLine(port.ToString(CultureInfo.InvariantCulture));
        }

        foreach (var peer in Peers)
        {
            sb.AppendLine();
            sb.Append(PeerNameComment).AppendLine(peer.Name);
            sb.AppendLine("[Peer]");
            sb.Append("PublicKey = ").AppendLine(peer.PublicKey.Value);
            if (peer.PresharedKey is not null)
            {
                sb.Append("PresharedKey = ").AppendLine(peer.PresharedKey.Reveal());
            }

            sb.Append("AllowedIPs = ").AppendLine(string.Join(", ", peer.AllowedIps));
            if (!string.IsNullOrEmpty(peer.Endpoint))
            {
                sb.Append("Endpoint = ").AppendLine(peer.Endpoint);
            }

            if (peer.PersistentKeepalive is { } ka)
            {
                sb.Append("PersistentKeepalive = ").AppendLine(ka.ToString(CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString().ReplaceLineEndings("\r\n");
    }

    /// <summary>Analyse un fichier produit par <see cref="Render"/> (ou compatible wg-quick).</summary>
    public static WgConfig Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        WgSecretKey? privateKey = null;
        var addresses = new List<string>();
        int? listenPort = null;
        var peers = new List<WgPeer>();
        string? section = null;
        string? pendingName = null;
        Dictionary<string, string>? peer = null;
        string? peerName = null;

        void FlushPeer()
        {
            if (peer is null)
            {
                return;
            }

            if (!peer.TryGetValue("publickey", out var pub))
            {
                throw new FormatException("Section [Peer] sans PublicKey.");
            }

            peers.Add(new WgPeer
            {
                Name = peerName ?? WgKeyFormat.Fingerprint(pub),
                PublicKey = new WgPublicKey(pub),
                PresharedKey = peer.TryGetValue("presharedkey", out var psk) ? new WgSecretKey(psk) : null,
                AllowedIps = peer.TryGetValue("allowedips", out var ips) ? SplitList(ips) : [],
                Endpoint = peer.TryGetValue("endpoint", out var ep) ? ep : null,
                PersistentKeepalive = peer.TryGetValue("persistentkeepalive", out var ka) ? int.Parse(ka, CultureInfo.InvariantCulture) : null,
            });
            peer = null;
            peerName = null;
        }

        var lineNo = 0;
        foreach (var raw in text.ReplaceLineEndings("\n").Split('\n'))
        {
            lineNo++;
            var line = raw.Trim();
            if (line.StartsWith(PeerNameComment.Trim(), StringComparison.Ordinal))
            {
                pendingName = line[PeerNameComment.Trim().Length..].Trim();
                continue;
            }

            var hash = line.IndexOf('#', StringComparison.Ordinal);
            if (hash >= 0)
            {
                line = line[..hash].Trim();
            }

            if (line.Length == 0)
            {
                continue;
            }

            if (line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase))
            {
                FlushPeer();
                section = "interface";
                continue;
            }

            if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase))
            {
                FlushPeer();
                section = "peer";
                peer = new Dictionary<string, string>(StringComparer.Ordinal);
                peerName = pendingName;
                pendingName = null;
                continue;
            }

            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                throw new FormatException(string.Create(CultureInfo.InvariantCulture, $"Ligne {lineNo} invalide dans la configuration WireGuard."));
            }

            var key = line[..eq].Trim().ToLowerInvariant();
            var value = line[(eq + 1)..].Trim();
            switch (section)
            {
                case "interface":
                    switch (key)
                    {
                        case "privatekey": privateKey = new WgSecretKey(value); break;
                        case "address": addresses.AddRange(SplitList(value)); break;
                        case "listenport": listenPort = int.Parse(value, CultureInfo.InvariantCulture); break;
                        default: break; // Clés non gérées (DNS, MTU…) ignorées : SecureDesk ne les produit pas.
                    }

                    break;
                case "peer":
                    peer![key] = value;
                    break;
                default:
                    throw new FormatException(string.Create(CultureInfo.InvariantCulture, $"Ligne {lineNo} hors section."));
            }
        }

        FlushPeer();
        return new WgConfig
        {
            Interface = new WgInterface
            {
                PrivateKey = privateKey ?? throw new FormatException("PrivateKey manquante dans [Interface]."),
                Addresses = addresses,
                ListenPort = listenPort,
            },
            Peers = peers,
        };
    }

    private static List<string> SplitList(string value) =>
        [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
}

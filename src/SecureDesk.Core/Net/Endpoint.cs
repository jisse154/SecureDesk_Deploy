using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SecureDesk.Core.Net;

public static partial class Endpoint
{
    [GeneratedRegex(@"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\.?$", RegexOptions.CultureInvariant)]
    private static partial Regex DnsNameRegex();

    /// <summary>Accepte une IPv4, une IPv6 ou un nom DNS (DDNS).</summary>
    public static bool IsValidHost(string? host, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(host))
        {
            error = "L'endpoint public est vide.";
            return false;
        }

        host = host.Trim();
        if (Ipv4Cidr.TryParseAddress(host, out _))
        {
            return true;
        }

        if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return true;
        }

        if (DnsNameRegex().IsMatch(host))
        {
            return true;
        }

        error = $"« {host} » n'est ni une adresse IP ni un nom DNS valide.";
        return false;
    }

    /// <summary>Format « hôte:port » pour WireGuard (IPv6 entre crochets).</summary>
    public static string Format(string host, int port)
    {
        ArgumentNullException.ThrowIfNull(host);
        host = host.Trim();
        var isV6 = IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6;
        var p = port.ToString(CultureInfo.InvariantCulture);
        return isV6 ? $"[{host}]:{p}" : $"{host}:{p}";
    }

    public static bool IsValidPort(int port) => port is >= 1 and <= 65535;
}

public static class PortSuggester
{
    public const int MinPort = 20000;
    public const int MaxPort = 60999;

    /// <summary>Ports bien connus à éviter (VPN, RDP, bases de données, jeux, etc.).</summary>
    public static readonly IReadOnlySet<int> Avoid = new HashSet<int>
    {
        51820, 51821, 1194, 1701, 1723, 500, 4500, 3389, 3390, 5900, 5938, 8080, 8443,
        27015, 27016, 25565, 32400, 33434, 47808, 49152, 50000, 54321, 55555,
    };

    public static int Suggest(Func<int, bool>? isInUse = null)
    {
        for (var attempt = 0; attempt < 1000; attempt++)
        {
            var port = RandomNumberGenerator.GetInt32(MinPort, MaxPort + 1);
            if (!Avoid.Contains(port) && (isInUse is null || !isInUse(port)))
            {
                return port;
            }
        }

        throw new InvalidOperationException("Impossible de trouver un port UDP libre.");
    }
}

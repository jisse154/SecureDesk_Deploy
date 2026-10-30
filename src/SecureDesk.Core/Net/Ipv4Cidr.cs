using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SecureDesk.Core.Net;

/// <summary>Sous-réseau IPv4 en notation CIDR (ex. 10.77.0.0/24).</summary>
public readonly record struct Ipv4Cidr
{
    public uint Network { get; }
    public int PrefixLength { get; }

    public Ipv4Cidr(uint network, int prefixLength)
    {
        if (prefixLength is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength), "Le préfixe doit être compris entre 0 et 32.");
        }

        PrefixLength = prefixLength;
        Network = network & MaskFor(prefixLength);
    }

    public uint Mask => MaskFor(PrefixLength);
    public uint Broadcast => Network | ~Mask;
    public ulong Size => 1UL << (32 - PrefixLength);

    public static uint MaskFor(int prefixLength) => prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);

    public static Ipv4Cidr Parse(string text)
    {
        if (!TryParse(text, out var cidr, out var error))
        {
            throw new FormatException(error);
        }

        return cidr;
    }

    public static bool TryParse(string? text, out Ipv4Cidr cidr, out string error)
    {
        cidr = default;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "Sous-réseau vide.";
            return false;
        }

        var parts = text.Trim().Split('/');
        if (parts.Length != 2)
        {
            error = $"« {text} » n'est pas au format a.b.c.d/n.";
            return false;
        }

        if (!TryParseAddress(parts[0], out var address))
        {
            error = $"Adresse IPv4 invalide : « {parts[0]} ».";
            return false;
        }

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) || prefix is < 0 or > 32)
        {
            error = $"Longueur de préfixe invalide : « {parts[1]} ».";
            return false;
        }

        if ((address & ~MaskFor(prefix)) != 0)
        {
            error = $"« {text} » n'est pas une adresse de réseau (bits d'hôte non nuls).";
            return false;
        }

        cidr = new Ipv4Cidr(address, prefix);
        return true;
    }

    public static bool TryParseAddress(string? text, out uint address)
    {
        address = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var octets = text.Trim().Split('.');
        if (octets.Length != 4)
        {
            return false;
        }

        foreach (var octet in octets)
        {
            if (octet.Length is 0 or > 3 || !byte.TryParse(octet, NumberStyles.None, CultureInfo.InvariantCulture, out var b))
            {
                return false;
            }

            address = (address << 8) | b;
        }

        return true;
    }

    public static uint ParseAddress(string text) =>
        TryParseAddress(text, out var a) ? a : throw new FormatException($"Adresse IPv4 invalide : « {text} ».");

    public static string FormatAddress(uint address) =>
        string.Create(CultureInfo.InvariantCulture, $"{address >> 24}.{(address >> 16) & 0xFF}.{(address >> 8) & 0xFF}.{address & 0xFF}");

    public static Ipv4Cidr FromAddressAndMask(IPAddress address, IPAddress mask)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(mask);
        if (address.AddressFamily != AddressFamily.InterNetwork || mask.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("IPv4 attendu.");
        }

        var a = ParseAddress(address.ToString());
        var m = ParseAddress(mask.ToString());
        var prefix = 0;
        while (prefix < 32 && (m & (0x8000_0000u >> prefix)) != 0)
        {
            prefix++;
        }

        if (MaskFor(prefix) != m)
        {
            throw new ArgumentException("Masque de sous-réseau non contigu.");
        }

        return new Ipv4Cidr(a, prefix);
    }

    public bool Contains(uint address) => (address & Mask) == Network;

    public bool Contains(string address) => TryParseAddress(address, out var a) && Contains(a);

    public bool Overlaps(Ipv4Cidr other) => Contains(other.Network) || other.Contains(Network);

    /// <summary>Adresse d'hôte n° <paramref name="index"/> (1 = première adresse utilisable).</summary>
    public uint Host(int index)
    {
        if (index < 1 || (ulong)index >= Size - (PrefixLength <= 30 ? 1UL : 0UL))
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"L'hôte n° {index} n'existe pas dans {this}.");
        }

        return Network + (uint)index;
    }

    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{FormatAddress(Network)}/{PrefixLength}");
}

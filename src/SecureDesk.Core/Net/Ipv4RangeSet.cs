namespace SecureDesk.Core.Net;

/// <summary>Plage IPv4 inclusive [Start, End].</summary>
public readonly record struct Ipv4Range(uint Start, uint End)
{
    public override string ToString() =>
        Start == End ? Ipv4Cidr.FormatAddress(Start) : $"{Ipv4Cidr.FormatAddress(Start)}-{Ipv4Cidr.FormatAddress(End)}";
}

public static class Ipv4RangeSet
{
    /// <summary>
    /// Calcule le complément exact (dans 0.0.0.0 – 255.255.255.255) de l'union des sous-réseaux autorisés.
    /// Utilisé pour la règle de blocage : une règle « block » Windows l'emporte sur une règle « allow »,
    /// il faut donc bloquer tout SAUF les plages autorisées.
    /// </summary>
    public static IReadOnlyList<Ipv4Range> Complement(IEnumerable<Ipv4Cidr> allowed)
    {
        ArgumentNullException.ThrowIfNull(allowed);
        var merged = Merge(allowed.Select(c => new Ipv4Range(c.Network, c.Broadcast)));
        var result = new List<Ipv4Range>();
        ulong cursor = 0;
        foreach (var r in merged)
        {
            if (r.Start > cursor)
            {
                result.Add(new Ipv4Range((uint)cursor, r.Start - 1));
            }

            cursor = (ulong)r.End + 1;
        }

        if (cursor <= uint.MaxValue)
        {
            result.Add(new Ipv4Range((uint)cursor, uint.MaxValue));
        }

        return result;
    }

    public static IReadOnlyList<Ipv4Range> Merge(IEnumerable<Ipv4Range> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        var sorted = ranges.OrderBy(r => r.Start).ToList();
        var result = new List<Ipv4Range>();
        foreach (var r in sorted)
        {
            if (result.Count > 0 && (ulong)result[^1].End + 1 >= r.Start)
            {
                var last = result[^1];
                result[^1] = last with { End = Math.Max(last.End, r.End) };
            }
            else
            {
                result.Add(r);
            }
        }

        return result;
    }
}

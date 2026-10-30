using System.Buffers.Binary;
using System.Net.Sockets;

namespace SecureDesk.Core.Time;

/// <summary>Client SNTP minimal (RFC 4330) pour mesurer la dérive de l'horloge locale.</summary>
public static class Sntp
{
    public static readonly TimeSpan MaxAllowedDrift = TimeSpan.FromSeconds(30);
    private static readonly DateTime NtpEpoch = new(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static byte[] BuildRequest()
    {
        var packet = new byte[48];
        packet[0] = 0x23; // LI = 0, VN = 4, Mode = 3 (client)
        return packet;
    }

    public static DateTime ReadTimestamp(ReadOnlySpan<byte> packet, int offset)
    {
        var seconds = BinaryPrimitives.ReadUInt32BigEndian(packet[offset..]);
        var fraction = BinaryPrimitives.ReadUInt32BigEndian(packet[(offset + 4)..]);
        var ticks = (long)seconds * TimeSpan.TicksPerSecond + (long)((double)fraction / uint.MaxValue * TimeSpan.TicksPerSecond);
        return NtpEpoch.AddTicks(ticks);
    }

    public static void WriteTimestamp(Span<byte> packet, int offset, DateTime utc)
    {
        var span = utc - NtpEpoch;
        var seconds = (uint)(span.Ticks / TimeSpan.TicksPerSecond);
        var fraction = (uint)((double)(span.Ticks % TimeSpan.TicksPerSecond) / TimeSpan.TicksPerSecond * uint.MaxValue);
        BinaryPrimitives.WriteUInt32BigEndian(packet[offset..], seconds);
        BinaryPrimitives.WriteUInt32BigEndian(packet[(offset + 4)..], fraction);
    }

    /// <summary>
    /// Décalage d'horloge = ((T2 − T1) + (T3 − T4)) / 2. Positif : l'horloge locale retarde.
    /// T1 = émission locale, T2 = réception serveur (octet 32), T3 = émission serveur (octet 40), T4 = réception locale.
    /// </summary>
    public static TimeSpan ComputeOffset(ReadOnlySpan<byte> response, DateTime t1, DateTime t4)
    {
        if (response.Length < 48)
        {
            throw new FormatException("Réponse SNTP trop courte.");
        }

        var mode = response[0] & 0x7;
        if (mode != 4)
        {
            throw new FormatException("Réponse SNTP invalide (mode).");
        }

        if (response[1] == 0)
        {
            throw new FormatException("Le serveur NTP a répondu « kiss-o'-death » (strate 0).");
        }

        var t2 = ReadTimestamp(response, 32);
        var t3 = ReadTimestamp(response, 40);
        return TimeSpan.FromTicks(((t2 - t1) + (t3 - t4)).Ticks / 2);
    }

    public static async Task<TimeSpan> MeasureOffsetAsync(string server, TimeSpan timeout, CancellationToken ct = default)
    {
        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;
        udp.Connect(server, 123);
        var request = BuildRequest();
        var t1 = DateTime.UtcNow;
        WriteTimestamp(request, 40, t1);
        await udp.SendAsync(request, ct).ConfigureAwait(false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
        var t4 = DateTime.UtcNow;
        return ComputeOffset(result.Buffer, t1, t4);
    }
}

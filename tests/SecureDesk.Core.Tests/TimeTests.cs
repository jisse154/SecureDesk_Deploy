using SecureDesk.Core.Time;

namespace SecureDesk.Core.Tests;

public class TimeTests
{
    [Fact]
    public void Calcul_du_decalage_sntp()
    {
        var t1 = new DateTime(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);
        var serverAhead = TimeSpan.FromSeconds(42);
        var oneWay = TimeSpan.FromMilliseconds(20);
        var response = new byte[48];
        response[0] = 0x24; // LI 0, VN 4, mode 4 (serveur)
        response[1] = 2;    // strate
        Sntp.WriteTimestamp(response, 32, t1 + oneWay + serverAhead);
        Sntp.WriteTimestamp(response, 40, t1 + oneWay + serverAhead + TimeSpan.FromMilliseconds(1));
        var t4 = t1 + oneWay + oneWay + TimeSpan.FromMilliseconds(1);
        var offset = Sntp.ComputeOffset(response, t1, t4);
        Assert.InRange(offset.TotalSeconds, 41.99, 42.01);
        Assert.True(offset > Sntp.MaxAllowedDrift);
    }

    [Fact]
    public void Reponse_sntp_invalide()
    {
        var bad = new byte[48];
        bad[0] = 0x23;
        Assert.Throws<FormatException>(() => Sntp.ComputeOffset(bad, DateTime.UtcNow, DateTime.UtcNow));
        var kod = new byte[48];
        kod[0] = 0x24;
        Assert.Throws<FormatException>(() => Sntp.ComputeOffset(kod, DateTime.UtcNow, DateTime.UtcNow));
        Assert.Throws<FormatException>(() => Sntp.ComputeOffset(new byte[10], DateTime.UtcNow, DateTime.UtcNow));
    }

    [Fact]
    public void Timestamp_ntp_aller_retour()
    {
        var t = new DateTime(2030, 1, 2, 3, 4, 5, 678, DateTimeKind.Utc);
        var buf = new byte[48];
        Sntp.WriteTimestamp(buf, 40, t);
        Assert.InRange((Sntp.ReadTimestamp(buf, 40) - t).TotalMilliseconds, -1, 1);
    }
}

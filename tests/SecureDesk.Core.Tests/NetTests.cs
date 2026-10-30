using SecureDesk.Core.Net;

namespace SecureDesk.Core.Tests;

public class NetTests
{
    [Theory]
    [InlineData("10.77.0.0/24", "10.77.0.0", 24)]
    [InlineData("192.168.1.0/24", "192.168.1.0", 24)]
    [InlineData("0.0.0.0/0", "0.0.0.0", 0)]
    [InlineData("10.0.0.1/32", "10.0.0.1", 32)]
    public void Parse_cidr_valide(string text, string network, int prefix)
    {
        var c = Ipv4Cidr.Parse(text);
        Assert.Equal(network, Ipv4Cidr.FormatAddress(c.Network));
        Assert.Equal(prefix, c.PrefixLength);
        Assert.Equal(text, c.ToString());
    }

    [Theory]
    [InlineData("10.77.0.1/24")]
    [InlineData("10.77.0.0")]
    [InlineData("10.77.0.0/33")]
    [InlineData("256.0.0.0/8")]
    [InlineData("10.77.0/24")]
    [InlineData("")]
    public void Parse_cidr_invalide(string text)
    {
        Assert.False(Ipv4Cidr.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Hotes_et_appartenance()
    {
        var c = Ipv4Cidr.Parse("10.77.0.0/24");
        Assert.Equal("10.77.0.1", Ipv4Cidr.FormatAddress(c.Host(1)));
        Assert.Equal("10.77.0.254", Ipv4Cidr.FormatAddress(c.Host(254)));
        Assert.Throws<ArgumentOutOfRangeException>(() => c.Host(255));
        Assert.Throws<ArgumentOutOfRangeException>(() => c.Host(0));
        Assert.True(c.Contains("10.77.0.200"));
        Assert.False(c.Contains("10.77.1.1"));
        Assert.True(c.Overlaps(Ipv4Cidr.Parse("10.0.0.0/8")));
        Assert.False(c.Overlaps(Ipv4Cidr.Parse("192.168.1.0/24")));
    }

    [Fact]
    public void Complement_exclut_exactement_les_plages_autorisees()
    {
        var allowed = new[] { Ipv4Cidr.Parse("10.77.0.0/24"), Ipv4Cidr.Parse("192.168.1.0/24") };
        var comp = Ipv4RangeSet.Complement(allowed);
        Assert.Equal(
            ["0.0.0.0-10.76.255.255", "10.77.1.0-192.168.0.255", "192.168.2.0-255.255.255.255"],
            comp.Select(r => r.ToString()).ToArray());
    }

    [Fact]
    public void Complement_propriete_aleatoire_couverture_exacte()
    {
        var rnd = new Random(1234);
        for (var iter = 0; iter < 300; iter++)
        {
            var allowed = Enumerable.Range(0, rnd.Next(1, 5))
                .Select(_ => new Ipv4Cidr((uint)rnd.NextInt64(0, uint.MaxValue), rnd.Next(4, 33)))
                .ToList();
            var comp = Ipv4RangeSet.Complement(allowed);

            // Plages triées, disjointes, non adjacentes aux autorisées.
            for (var i = 1; i < comp.Count; i++)
            {
                Assert.True(comp[i].Start > comp[i - 1].End);
            }

            for (var k = 0; k < 200; k++)
            {
                var a = (uint)rnd.NextInt64(0, (long)uint.MaxValue + 1);
                var isAllowed = allowed.Any(c => c.Contains(a));
                var isBlocked = comp.Any(r => a >= r.Start && a <= r.End);
                Assert.NotEqual(isAllowed, isBlocked);
            }

            foreach (var c in allowed)
            {
                Assert.DoesNotContain(comp, r => c.Network >= r.Start && c.Network <= r.End);
                Assert.DoesNotContain(comp, r => c.Broadcast >= r.Start && c.Broadcast <= r.End);
            }
        }
    }

    [Fact]
    public void Complement_de_tout_est_vide()
    {
        Assert.Empty(Ipv4RangeSet.Complement([Ipv4Cidr.Parse("0.0.0.0/0")]));
    }

    [Theory]
    [InlineData("monbureau.ddns.net", true)]
    [InlineData("82.64.10.20", true)]
    [InlineData("2001:db8::1", true)]
    [InlineData("bureau", false)]
    [InlineData("-bad.example.com", false)]
    [InlineData("", false)]
    [InlineData("a b.com", false)]
    public void Validation_endpoint(string host, bool ok)
    {
        Assert.Equal(ok, Endpoint.IsValidHost(host, out _));
    }

    [Fact]
    public void Format_endpoint_ipv6_entre_crochets()
    {
        Assert.Equal("[2001:db8::1]:40123", Endpoint.Format("2001:db8::1", 40123));
        Assert.Equal("x.ddns.net:40123", Endpoint.Format("x.ddns.net", 40123));
    }

    [Fact]
    public void Port_suggere_hors_ports_connus()
    {
        for (var i = 0; i < 500; i++)
        {
            var p = PortSuggester.Suggest();
            Assert.InRange(p, PortSuggester.MinPort, PortSuggester.MaxPort);
            Assert.DoesNotContain(p, PortSuggester.Avoid);
        }
    }

    [Fact]
    public void Port_suggere_evite_les_ports_occupes()
    {
        var p = PortSuggester.Suggest(port => port % 2 == 0);
        Assert.Equal(1, p % 2);
    }
}

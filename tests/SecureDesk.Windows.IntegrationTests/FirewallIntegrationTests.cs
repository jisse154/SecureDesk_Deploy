using SecureDesk.Core.Firewall;
using SecureDesk.Core.Net;
using SecureDesk.Windows.Firewall;

namespace SecureDesk.Windows.IntegrationTests;

[Collection("systeme")]
public class FirewallIntegrationTests
{
    [Fact]
    public void Regles_creees_conformes_idempotentes_puis_supprimees()
    {
        if (!Integration.Enabled)
        {
            return;
        }

        var log = Integration.Log();
        var fw = new FirewallOps(log, Integration.Runner(log));
        var rules = FirewallPlan.Build(Ipv4Cidr.Parse("10.77.0.0/24"), Ipv4Cidr.Parse("192.168.50.0/24"), 3389, [80, 443], 51999);
        try
        {
            foreach (var r in rules)
            {
                fw.Apply(r);
            }

            // Deuxième passage : remplacement, jamais de doublon.
            foreach (var r in rules)
            {
                fw.Apply(r);
            }

            var owned = fw.OwnedRules();
            Assert.Equal(rules.Count, owned.Count);
            Assert.Equal(rules.Count, owned.Select(o => o.Name).Distinct().Count());
            foreach (var r in rules)
            {
                Assert.True(FirewallOps.IsCompliant(r, owned), $"Règle non conforme après relecture : {r.Name} → {owned.First(o => o.Name == r.Name).RemoteAddresses}");
            }
        }
        finally
        {
            fw.RemoveAllOwned();
        }

        Assert.Empty(fw.OwnedRules());
    }
}

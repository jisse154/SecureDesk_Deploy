using SecureDesk.Core.Engine;
using SecureDesk.Core.Logging;
using SecureDesk.Core.State;

namespace SecureDesk.Core.Tests;

public class EngineAndStateTests
{
    private sealed class FakeSetting
    {
        public string? Value { get; set; }
    }

    private static Step SetStep(FakeSetting s, string target, Action? onApply = null) =>
        new("set", "Régler la valeur", () => s.Value == target ? StepCheck.Ok() : StepCheck.Change($"{s.Value} → {target}"), () =>
        {
            onApply?.Invoke();
            s.Value = target;
        });

    [Fact]
    public void Dry_run_ne_modifie_rien()
    {
        var s = new FakeSetting { Value = "a" };
        var r = new StepRunner(NullLog.Instance).Run([SetStep(s, "b")], dryRun: true);
        Assert.Equal("a", s.Value);
        Assert.Equal(StepOutcome.WouldApply, Assert.Single(r.Steps).Outcome);
        Assert.True(r.Success);
    }

    [Fact]
    public void Idempotence_seconde_execution_sans_effet()
    {
        var s = new FakeSetting { Value = "a" };
        var applies = 0;
        var runner = new StepRunner(NullLog.Instance);
        var first = runner.Run([SetStep(s, "b", () => applies++)], dryRun: false);
        var second = runner.Run([SetStep(s, "b", () => applies++)], dryRun: false);
        Assert.Equal(StepOutcome.Applied, first.Steps[0].Outcome);
        Assert.Equal(StepOutcome.AlreadyCompliant, second.Steps[0].Outcome);
        Assert.Equal(1, applies);
    }

    [Fact]
    public void Arret_a_la_premiere_erreur()
    {
        var log = new MemoryLog();
        var ran = false;
        var steps = new IStep[]
        {
            new Step("boom", "Étape en échec", () => StepCheck.Change(), () => throw new InvalidOperationException("panne simulée")),
            new Step("next", "Suivante", () => StepCheck.Change(), () => ran = true),
        };
        var r = new StepRunner(log).Run(steps, dryRun: false);
        Assert.False(r.Success);
        Assert.Single(r.Steps);
        Assert.False(ran);
        Assert.Contains("panne simulée", log.AllText(), StringComparison.Ordinal);
    }

    [Fact]
    public void Valeur_d_origine_jamais_ecrasee()
    {
        var st = new SecureDeskState();
        Assert.True(st.RecordOriginal("reg:x", "registry", new Dictionary<string, string?> { ["value"] = "orig" }));
        Assert.False(st.RecordOriginal("reg:x", "registry", new Dictionary<string, string?> { ["value"] = "deja-modifie" }));
        Assert.Equal("orig", Assert.Single(st.Rollback).Data["value"]);
    }

    [Fact]
    public void Etat_aller_retour_fichier()
    {
        var path = Path.Combine(Path.GetTempPath(), "sd-state-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new FileStateStore(path);
            var st = store.Load();
            st.Role = "server";
            st.Server = new ServerState { TunnelName = "securedesk", ListenPort = 41234 };
            st.Server.Peers.Add(new PeerRecord { Name = "pc-perso", TunnelIp = "10.77.0.2" });
            store.Save(st);
            var back = store.Load();
            Assert.Equal("server", back.Role);
            Assert.Equal("pc-perso", Assert.Single(back.Server!.Peers).Name);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

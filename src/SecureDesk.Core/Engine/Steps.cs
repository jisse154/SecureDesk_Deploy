using System.Globalization;
using SecureDesk.Core.Logging;

namespace SecureDesk.Core.Engine;

public enum StepStatus
{
    /// <summary>L'état voulu est déjà en place : rien à faire (idempotence).</summary>
    Compliant,

    /// <summary>Une modification est nécessaire.</summary>
    NeedsChange,

    /// <summary>Étape sans objet dans cette configuration.</summary>
    NotApplicable,
}

public sealed record StepCheck(StepStatus Status, string? Detail = null)
{
    public static StepCheck Ok(string? detail = null) => new(StepStatus.Compliant, detail);
    public static StepCheck Change(string? detail = null) => new(StepStatus.NeedsChange, detail);
    public static StepCheck Skip(string? detail = null) => new(StepStatus.NotApplicable, detail);
}

/// <summary>Une opération idempotente : vérifier (lecture seule), puis appliquer si nécessaire.</summary>
public interface IStep
{
    string Id { get; }
    string Title { get; }

    /// <summary>Lecture seule : ne doit jamais modifier le système (utilisé par --dry-run).</summary>
    StepCheck Check();

    void Apply();
}

public sealed class Step(string id, string title, Func<StepCheck> check, Action apply) : IStep
{
    public string Id { get; } = id;
    public string Title { get; } = title;
    public StepCheck Check() => check();
    public void Apply() => apply();
}

public enum StepOutcome
{
    AlreadyCompliant,
    Applied,
    WouldApply,
    Skipped,
    Failed,
}

public sealed record StepResult(string Id, string Title, StepOutcome Outcome, string? Detail);

public sealed record RunResult(IReadOnlyList<StepResult> Steps)
{
    public bool Success => Steps.All(s => s.Outcome != StepOutcome.Failed);

    public string Summary()
    {
        var lines = Steps.Select(s => $"  [{Label(s.Outcome)}] {s.Title}{(string.IsNullOrEmpty(s.Detail) ? string.Empty : " — " + s.Detail)}");
        return string.Join(Environment.NewLine, lines);
    }

    public static string Label(StepOutcome o) => o switch
    {
        StepOutcome.AlreadyCompliant => "déjà conforme",
        StepOutcome.Applied => "fait",
        StepOutcome.WouldApply => "à faire",
        StepOutcome.Skipped => "sans objet",
        StepOutcome.Failed => "ÉCHEC",
        _ => o.ToString(),
    };
}

public sealed class StepRunner(ILog log)
{
    /// <summary>
    /// Exécute les étapes dans l'ordre. En dry-run, seules les vérifications (lecture seule) sont faites.
    /// Arrêt à la première erreur : les étapes suivantes dépendent généralement des précédentes.
    /// </summary>
    public RunResult Run(IEnumerable<IStep> steps, bool dryRun, IProgress<StepResult>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(steps);
        var results = new List<StepResult>();
        foreach (var step in steps)
        {
            StepResult result;
            try
            {
                var check = step.Check();
                switch (check.Status)
                {
                    case StepStatus.Compliant:
                        result = new(step.Id, step.Title, StepOutcome.AlreadyCompliant, check.Detail);
                        break;
                    case StepStatus.NotApplicable:
                        result = new(step.Id, step.Title, StepOutcome.Skipped, check.Detail);
                        break;
                    default:
                        if (dryRun)
                        {
                            result = new(step.Id, step.Title, StepOutcome.WouldApply, check.Detail);
                        }
                        else
                        {
                            log.Info($"→ {step.Title}");
                            step.Apply();
                            result = new(step.Id, step.Title, StepOutcome.Applied, check.Detail);
                        }

                        break;
                }
            }
#pragma warning disable CA1031 // Toute erreur d'une étape est rapportée proprement et arrête la suite.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                log.Error(string.Create(CultureInfo.InvariantCulture, $"Échec de l'étape « {step.Title} » : {ex.Message}"));
                log.Debug(ex.ToString());
                result = new(step.Id, step.Title, StepOutcome.Failed, ex.Message);
            }

            results.Add(result);
            log.Info($"[{RunResult.Label(result.Outcome)}] {result.Title}{(result.Detail is null ? string.Empty : " — " + result.Detail)}");
            progress?.Report(result);
            if (result.Outcome == StepOutcome.Failed)
            {
                break;
            }
        }

        return new RunResult(results);
    }
}

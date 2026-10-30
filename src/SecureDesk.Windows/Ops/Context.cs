using System.Security.Cryptography;
using SecureDesk.Core.Config;
using SecureDesk.Core.Engine;
using SecureDesk.Core.Installers;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Security;
using SecureDesk.Core.State;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.Ops;

/// <summary>Interaction avec l'utilisateur : implémentée en console (CLI) et en WinForms (assistant).</summary>
public interface IUi
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);

    /// <summary>Affiche un bloc important (instructions, checklist) et attend la lecture.</summary>
    void Show(string title, IReadOnlyList<string> lines);

    bool Confirm(string question, bool defaultAnswer = false);
    string Ask(string question, string? defaultValue = null);
    SensitiveText AskSecret(string prompt, bool confirm);

    /// <summary>Affiche le QR code une seule fois ; retourne quand l'utilisateur a scanné. Rien n'est écrit sur disque.</summary>
    void ShowQrOnce(string title, string provisioningText);

    /// <summary>Affiche des codes de secours une seule fois.</summary>
    void ShowSecretsOnce(string title, IReadOnlyList<string> lines);
}

public sealed class OperationException(string message) : Exception(message);

/// <summary>Contexte partagé d'une exécution.</summary>
public sealed class Context
{
    public Context(ILog log, IUi ui, SecureDeskConfig config, IStateStore store, bool dryRun)
    {
        Log = log;
        Ui = ui;
        Config = config;
        Store = store;
        DryRun = dryRun;
        Runner = new ProcessRunner(log);
        State = store.Load();
        Manifest = InstallerManifest.Embedded();
    }

    public ILog Log { get; }
    public IUi Ui { get; }
    public SecureDeskConfig Config { get; }
    public IStateStore Store { get; }
    public SecureDeskState State { get; }
    public bool DryRun { get; }
    public ProcessRunner Runner { get; }
    public InstallerManifest Manifest { get; }
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>Empreinte SHA-256 fournie par l'utilisateur pour un installeur non épinglé (--sha256).</summary>
    public string? Sha256Override { get; init; }

    public bool ConsoleAccessAcknowledged { get; init; }

    /// <summary>Mode non interactif (--yes) : les suppressions de fichiers ne sont jamais faites automatiquement.</summary>
    public bool AssumeYes { get; init; }

    public void Save()
    {
        if (!DryRun)
        {
            SecureFiles.EnsureProtectedDirectory(SecureFiles.ProgramDataRoot);
            Store.Save(State);
        }
    }

    public RunResult Run(IEnumerable<IStep> steps)
    {
        var result = new StepRunner(Log).Run(steps, DryRun);
        Save();
        foreach (var s in result.Steps)
        {
            var line = $"[{RunResult.Label(s.Outcome)}] {s.Title}{(string.IsNullOrEmpty(s.Detail) ? string.Empty : " — " + s.Detail)}";
            if (s.Outcome == StepOutcome.Failed)
            {
                Ui.Error(line);
            }
            else
            {
                Ui.Info(line);
            }
        }

        if (!result.Success)
        {
            throw new OperationException("Opération interrompue. Corrigez le problème signalé puis relancez : l'outil reprendra là où il s'est arrêté.");
        }

        return result;
    }

    public static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
}

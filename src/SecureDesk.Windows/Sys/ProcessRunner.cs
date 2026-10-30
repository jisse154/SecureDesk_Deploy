using System.Diagnostics;
using System.Globalization;
using System.Text;
using SecureDesk.Core.Logging;

namespace SecureDesk.Windows.Sys;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Ok => ExitCode == 0;
}

public sealed class ProcessFailedException(string message) : Exception(message);

/// <summary>
/// Lance un programme SANS shell (ArgumentList : aucune injection possible).
/// Les arguments marqués sensibles et l'entrée standard ne sont jamais journalisés.
/// </summary>
public sealed class ProcessRunner(ILog log)
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);

    public ProcessResult Run(string fileName, IEnumerable<string> args, string? stdin = null, TimeSpan? timeout = null, bool sensitiveArgs = false, bool logOutput = true)
    {
        ArgumentNullException.ThrowIfNull(args);
        return Start(fileName, args.ToList(), null, stdin, timeout, sensitiveArgs, logOutput);
    }

    /// <summary>
    /// Ligne de commande brute : réservée à msiexec, qui n'accepte pas l'échappement C (\") produit par ArgumentList
    /// pour PROPRIETE="" (il ouvre alors une fenêtre d'aide invisible et reste bloqué). Les valeurs sont validées par l'appelant.
    /// </summary>
    public ProcessResult RunRaw(string fileName, string rawArguments, TimeSpan? timeout = null) =>
        Start(fileName, [], rawArguments, null, timeout, sensitiveArgs: false, logOutput: true);

    private ProcessResult Start(string fileName, List<string> argList, string? rawArguments, string? stdin, TimeSpan? timeout, bool sensitiveArgs, bool logOutput)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        if (rawArguments is not null)
        {
            psi.Arguments = rawArguments;
        }

        foreach (var a in argList)
        {
            psi.ArgumentList.Add(a);
        }

        var shown = sensitiveArgs ? "(arguments masqués)" : rawArguments ?? string.Join(' ', argList.Select(Quote));
        log.Debug($"Exécution : {Path.GetFileName(fileName)} {shown}");
        using var p = Process.Start(psi) ?? throw new ProcessFailedException($"Impossible de lancer {fileName}.");
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        p.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                stdout.AppendLine(e.Data);
            }
        };
        p.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                stderr.AppendLine(e.Data);
            }
        };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        // Entrée standard toujours fermée : un outil tiers ne peut jamais rester bloqué en attente d'une saisie.
        if (stdin is not null)
        {
            p.StandardInput.Write(stdin);
        }

        p.StandardInput.Close();

        if (!p.WaitForExit(timeout ?? DefaultTimeout))
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw new ProcessFailedException($"Délai dépassé : {Path.GetFileName(fileName)}.");
        }

        p.WaitForExit();
        var result = new ProcessResult(p.ExitCode, stdout.ToString(), stderr.ToString());
        if (logOutput)
        {
            log.Debug(string.Create(CultureInfo.InvariantCulture, $"Code retour {result.ExitCode}. {Trim(result.StdOut)} {Trim(result.StdErr)}"));
        }

        return result;
    }

    public ProcessResult RunChecked(string fileName, IEnumerable<string> args, string? stdin = null, TimeSpan? timeout = null, bool sensitiveArgs = false, params int[] okCodes) =>
        Check(fileName, Run(fileName, args, stdin, timeout, sensitiveArgs), okCodes);

    public ProcessResult RunRawChecked(string fileName, string rawArguments, TimeSpan? timeout = null, params int[] okCodes) =>
        Check(fileName, RunRaw(fileName, rawArguments, timeout), okCodes);

    private static ProcessResult Check(string fileName, ProcessResult r, int[] okCodes)
    {
        var accepted = okCodes is { Length: > 0 } ? okCodes : [0];
        if (!accepted.Contains(r.ExitCode))
        {
            throw new ProcessFailedException(string.Create(CultureInfo.InvariantCulture,
                $"{Path.GetFileName(fileName)} a échoué (code {r.ExitCode}) : {Redactor.Redact(Trim(r.StdErr + " " + r.StdOut))}"));
        }

        return r;
    }

    public static string SystemExe(string name) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);

    private static string Quote(string a) => a.Contains(' ', StringComparison.Ordinal) ? "\"" + a + "\"" : a;

    private static string Trim(string s)
    {
        s = s.Trim().ReplaceLineEndings(" ");
        return s.Length > 500 ? s[..500] + "…" : s;
    }
}

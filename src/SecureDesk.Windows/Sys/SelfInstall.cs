using System.Globalization;
using System.Security;
using System.Text;
using SecureDesk.Core.Logging;

namespace SecureDesk.Windows.Sys;

/// <summary>
/// Copie de l'outil dans %ProgramFiles%\SecureDesk : disable-2fa doit rester disponible à la console
/// même si l'exécutable d'origine était sur une clé USB.
/// </summary>
public sealed class SelfInstall(ILog log, ProcessRunner runner)
{
    public static string Dir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SecureDesk");
    public static string Exe => Path.Combine(Dir, "SecureDesk.exe");

    public void EnsureInstalled()
    {
        var current = Environment.ProcessPath;
        if (current is null || !current.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            log.Debug("Exécution hors exécutable publié : copie dans Program Files ignorée.");
            return;
        }

        if (string.Equals(Path.GetFullPath(current), Path.GetFullPath(Exe), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        SecureFiles.EnsureProtectedDirectory(Dir);
        File.Copy(current, Exe, overwrite: true);
        new FileInfo(Exe).SetAccessControl(SecureFiles.ProtectedFileSecurity());
        log.Info($"SecureDesk copié dans {Exe} (disponible pour disable-2fa à la console).");
    }

    public void Remove()
    {
        if (Directory.Exists(Dir) && !string.Equals(Path.GetDirectoryName(Environment.ProcessPath), Dir, StringComparison.OrdinalIgnoreCase))
        {
            Directory.Delete(Dir, recursive: true);
        }
    }

    // ---------- Tâche planifiée de désactivation automatique (activation probatoire du 2FA) ----------

    public const string ProbationTaskName = @"\SecureDesk\Desactivation-2FA-probatoire";

    /// <summary>
    /// Crée une tâche SYSTEM unique via une définition XML (date ISO 8601 : indépendante des paramètres régionaux,
    /// contrairement à « schtasks /sd »).
    /// </summary>
    public void ScheduleProbation(DateTimeOffset whenUtc)
    {
        var local = whenUtc.ToLocalTime();
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Description>SecureDesk : désactive le 2FA si « SecureDesk.exe confirm-2fa » n'a pas été exécuté (anti-verrouillage).</Description>
              </RegistrationInfo>
              <Triggers>
                <TimeTrigger>
                  <StartBoundary>{local.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture)}</StartBoundary>
                  <Enabled>true</Enabled>
                </TimeTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>S-1-5-18</UserId>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <StartWhenAvailable>true</StartWhenAvailable>
                <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
                <Enabled>true</Enabled>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{SecurityElement.Escape(Exe)}</Command>
                  <Arguments>disable-2fa --from-probation</Arguments>
                </Exec>
              </Actions>
            </Task>
            """;
        var tmp = Path.Combine(Path.GetTempPath(), "sd-task-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            File.WriteAllText(tmp, xml, Encoding.Unicode);
            runner.RunChecked(ProcessRunner.SystemExe("schtasks.exe"), ["/create", "/tn", ProbationTaskName, "/xml", tmp, "/f"]);
        }
        finally
        {
            File.Delete(tmp);
        }

        log.Info($"Tâche de désactivation automatique programmée à {local:HH:mm} (heure locale).");
    }

    public bool ProbationScheduled() =>
        runner.Run(ProcessRunner.SystemExe("schtasks.exe"), ["/query", "/tn", ProbationTaskName]).Ok;

    public void CancelProbation()
    {
        if (ProbationScheduled())
        {
            runner.RunChecked(ProcessRunner.SystemExe("schtasks.exe"), ["/delete", "/tn", ProbationTaskName, "/f"]);
        }
    }
}

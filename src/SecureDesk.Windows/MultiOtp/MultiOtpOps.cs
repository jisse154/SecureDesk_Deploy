using System.Globalization;
using Microsoft.Win32;
using SecureDesk.Core.Config;
using SecureDesk.Core.Installers;
using SecureDesk.Core.Logging;
using SecureDesk.Core.MultiOtp;
using SecureDesk.Core.State;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.MultiOtp;

public sealed record MultiOtpStatus(bool Installed, string? CpusLogon, string? CpusUnlock, string? CpusCredUi, string? Path, bool DllSigned)
{
    public bool Active => MultiOtpPlan.IsActive(CpusLogon);
}

/// <summary>
/// multiOTP Credential Provider en mode local (multiOTP embarqué, aucun serveur).
/// Toutes les valeurs et commandes proviennent du README officiel, de Product.wxs et de l'aide de la CLI multiotp.
/// </summary>
public sealed class MultiOtpOps(ILog log, ProcessRunner runner)
{
    private const string ClassesClsid = @"SOFTWARE\Classes\" + MultiOtpPlan.RegistryKey;

    /// <summary>DLL du Credential Provider (README : « installed in the system folder \Windows\System32 »).</summary>
    public static string ProviderDll => ProcessRunner.SystemExe("multiOTPCredentialProvider.dll");

    public static string? InstallPath()
    {
        var fromReg = RegistryOps.ReadString(ClassesClsid, "multiOTPPath");
        if (!string.IsNullOrEmpty(fromReg) && Directory.Exists(fromReg))
        {
            return fromReg;
        }

        var def = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "multiOTP");
        return Directory.Exists(def) ? def : null;
    }

    public static string? CliPath()
    {
        var dir = InstallPath();
        var exe = dir is null ? null : System.IO.Path.Combine(dir, "multiotp.exe");
        return exe is not null && File.Exists(exe) ? exe : null;
    }

    public static MultiOtpStatus Status()
    {
        var installed = File.Exists(ProviderDll) && CliPath() is not null;
        return new MultiOtpStatus(
            installed,
            RegistryOps.ReadString(ClassesClsid, "cpus_logon"),
            RegistryOps.ReadString(ClassesClsid, "cpus_unlock"),
            RegistryOps.ReadString(ClassesClsid, "cpus_credui"),
            InstallPath(),
            installed && Authenticode.Verify(ProviderDll).Valid);
    }

    // ---------- Installation (désactivé : cpus_* = 3d) ----------

    public void Install(InstallerManifest manifest, string? localMsi, string? localVcRedist, string? msiSha256)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var source = new InstallerSource(log, runner);
        if (!VcRedistInstalled())
        {
            var vc = source.Acquire(manifest.VcRedist, localVcRedist);
            runner.RunChecked(vc, ["/install", "/quiet", "/norestart"], timeout: TimeSpan.FromMinutes(10), okCodes: [0, 1638, 3010]);
            log.Info("Visual C++ Redistributable 2015-2022 x64 installé.");
        }

        var msi = source.Acquire(manifest.MultiOtp, localMsi, msiSha256);
        source.InstallMsi(msi, MultiOtpPlan.MsiProperties(), "multiotp-install.log");
        VerifyInstalled();
    }

    /// <summary>
    /// Contrôles post-installation. Le README avertit que l'installation silencieuse ne teste rien :
    /// on relit donc chaque valeur et on vérifie les signatures avant toute activation.
    /// </summary>
    public void VerifyInstalled()
    {
        var st = Status();
        if (!st.Installed)
        {
            throw new InvalidOperationException("multiOTP Credential Provider introuvable après installation.");
        }

        if (!st.DllSigned || !Authenticode.Verify(CliPath()!).Valid)
        {
            throw new InstallerVerificationException("La DLL du Credential Provider ou multiotp.exe n'a pas de signature Authenticode valide : désinstallez multiOTP et n'activez pas le 2FA.");
        }

        var problems = new List<string>();
        foreach (var (name, expected) in MultiOtpPlan.ExpectedAfterInstall())
        {
            var actual = RegistryOps.Read(ClassesClsid, name)?.ToString() ?? string.Empty;
            if (!string.Equals(actual, expected, StringComparison.Ordinal))
            {
                problems.Add($"{name} = « {actual} » (attendu « {expected} »)");
            }
        }

        if (problems.Count > 0)
        {
            // Correction directe des valeurs d'activation (seules celles-ci conditionnent la sécurité) puis signalement.
            SetDisabled();
            throw new InvalidOperationException("Paramètres multiOTP inattendus après installation : " + string.Join(" ; ", problems));
        }

        HardenFolders();
        log.Info("multiOTP Credential Provider installé et vérifié (INACTIF tant que enable-2fa n'a pas réussi).");
    }

    public static bool VcRedistInstalled()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var k = hklm.OpenSubKey(@"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64");
        return k?.GetValue("Installed") is int i && i == 1;
    }

    /// <summary>Retire la lecture aux utilisateurs sur les dossiers contenant graines et configuration (comme le fait l'installeur).</summary>
    public void HardenFolders()
    {
        var root = InstallPath();
        if (root is null)
        {
            return;
        }

        foreach (var sub in new[] { "config", "users", "tokens", "templates", "log", "cache" })
        {
            var dir = System.IO.Path.Combine(root, sub);
            if (Directory.Exists(dir))
            {
                SecureFiles.RevokeUsers(dir);
            }
        }
    }

    // ---------- Activation / désactivation (seules les valeurs cpus_*) ----------

    public void SetActive(TwoFactorScope scope, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        foreach (var (name, value) in MultiOtpPlan.ActivationValues(scope))
        {
            RegistryOps.RecordOriginal(ClassesClsid, name, state);
            using var hklm = RegistryOps.Hklm();
            using var key = hklm.OpenSubKey(ClassesClsid, writable: true) ?? throw new InvalidOperationException("Clé du Credential Provider absente.");
            key.SetValue(name, value, RegistryValueKind.String);
        }

        var st = Status();
        if (st.CpusLogon != MultiOtpPlan.ActivationValues(scope)["cpus_logon"])
        {
            SetDisabled();
            throw new InvalidOperationException("Relecture du registre incohérente : 2FA laissé désactivé.");
        }
    }

    /// <summary>Désactivation documentée : « 3 … multiOTP Credential Provider is completely disabled ».</summary>
    public void SetDisabled()
    {
        using var hklm = RegistryOps.Hklm();
        using var key = hklm.OpenSubKey(ClassesClsid, writable: true);
        if (key is null)
        {
            return;
        }

        foreach (var (name, value) in MultiOtpPlan.DisabledValues())
        {
            key.SetValue(name, value, RegistryValueKind.String);
        }

        log.Info("multiOTP Credential Provider désactivé (cpus_logon/cpus_unlock/cpus_credui = 3d).");
    }

    // ---------- CLI multiotp ----------

    private string Cli => CliPath() ?? throw new InvalidOperationException("multiotp.exe introuvable.");

    private ProcessResult RunCli(IEnumerable<string> args, bool sensitive = false) =>
        runner.Run(Cli, args, timeout: TimeSpan.FromMinutes(2), sensitiveArgs: sensitive, logOutput: false);

    public bool UserExists(string user)
    {
        var r = RunCli(["-user-info", user]);
        return r.ExitCode != MultiOtpExitCodes.UserDoesNotExist && r.StdOut.Trim().Length > 0;
    }

    /// <summary>Crée un jeton TOTP sans code PIN préfixe (« multiotp -fastcreatenopin user »).</summary>
    public void CreateUser(string user)
    {
        var r = RunCli(["-fastcreatenopin", user]);
        if (r.ExitCode is not (MultiOtpExitCodes.UserCreated or MultiOtpExitCodes.OperationDone or 0))
        {
            throw new InvalidOperationException($"multiOTP : création de « {user} » impossible ({MultiOtpExitCodes.Describe(r.ExitCode)}).");
        }
    }

    /// <summary>
    /// URI de provisionnement (« multiotp -urllink user ») capturée en MÉMOIRE uniquement : la graine ne passe ni en argument
    /// ni dans un fichier, et la sortie n'est jamais journalisée.
    /// </summary>
    public (OtpAuthUri Uri, string QrText) ProvisioningUri(string user)
    {
        var r = RunCli(["-urllink", user]);
        if (!OtpAuthUri.TryParse(r.StdOut, out var uri) || uri is null)
        {
            throw new InvalidOperationException($"multiOTP : lien de provisionnement introuvable ({MultiOtpExitCodes.Describe(r.ExitCode)}).");
        }

        return (uri, uri.ToProvisioningText(r.StdOut));
    }

    /// <summary>Vérifie un code (« multiotp user code » : 0 = accepté). Les arguments sont masqués dans le journal.</summary>
    public int CheckCode(string user, string code) => RunCli([user, code], sensitive: true).ExitCode;

    /// <summary>Codes de secours natifs (« multiotp -scratchlist user » : generate &amp; display scratch passwords).</summary>
    public IReadOnlyList<string> ScratchList(string user)
    {
        var root = InstallPath()!;
        var before = SnapshotFiles(root);
        var r = RunCli(["-scratchlist", user]);
        var codes = r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Length >= 6 && l.All(char.IsLetterOrDigit))
            .ToList();
        // Vérification documentée dans le plan : aucun fichier ne doit persister après l'opération.
        foreach (var f in SnapshotFiles(root).Except(before).Where(IsProvisioningArtifact))
        {
            SecureFiles.BestEffortWipe(f);
            log.Warn($"Fichier produit par multiOTP supprimé : {System.IO.Path.GetFileName(f)}");
        }

        if (codes.Count == 0)
        {
            throw new InvalidOperationException($"multiOTP : codes de secours non générés ({MultiOtpExitCodes.Describe(r.ExitCode)}).");
        }

        return codes;
    }

    public void DeleteUser(string user)
    {
        var r = RunCli(["-delete", user]);
        log.Info($"multiOTP : suppression de « {user} » ({MultiOtpExitCodes.Describe(r.ExitCode)}).");
    }

    public void Unlock(string user) => RunCli(["-unlock", user]);

    public IReadOnlyList<string> Users()
    {
        var r = RunCli(["-userslist"]);
        return [.. r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    }

    /// <summary>Fichiers QR/HTML résiduels (doivent être absents).</summary>
    public static IReadOnlyList<string> LeftoverProvisioningFiles()
    {
        var found = new List<string>();
        var roots = new[] { InstallPath(), System.IO.Path.GetTempPath() }.Where(r => r is not null && Directory.Exists(r));
        foreach (var root in roots)
        {
            try
            {
                found.AddRange(Directory.EnumerateFiles(root!, "*", SearchOption.AllDirectories).Where(IsProvisioningArtifact));
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return found;
    }

    private static bool IsProvisioningArtifact(string path)
    {
        var name = System.IO.Path.GetFileName(path).ToLowerInvariant();
        var ext = System.IO.Path.GetExtension(name);
        return (ext is ".png" or ".svg" || (ext == ".html" && !path.Contains("templates", StringComparison.OrdinalIgnoreCase)))
            && (name.Contains("qr", StringComparison.Ordinal) || name.Contains("multiotp", StringComparison.Ordinal) || name.Contains("scratch", StringComparison.Ordinal) || name.Contains("token", StringComparison.Ordinal));
    }

    private static HashSet<string> SnapshotFiles(string root) =>
        Directory.Exists(root) ? [.. Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)] : [];

    public static string DescribeScope(TwoFactorScope scope) => scope switch
    {
        TwoFactorScope.RemoteOnly => "connexions à distance uniquement (la console reste inchangée)",
        _ => "connexions à distance ET ouverture de session locale",
    };

    public static string FormatCodes(IReadOnlyList<string> codes) =>
        string.Join(Environment.NewLine, codes.Select((c, i) => string.Create(CultureInfo.InvariantCulture, $"  {i + 1,2}. {c}")));
}

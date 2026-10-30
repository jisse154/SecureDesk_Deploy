using System.Globalization;
using SecureDesk.Core.Installers;
using SecureDesk.Core.Logging;

namespace SecureDesk.Windows.Sys;

public sealed class InstallerVerificationException(string message) : Exception(message);

/// <summary>
/// Obtient un installeur officiel (fichier local fourni = mode hors ligne, sinon téléchargement HTTPS)
/// et le vérifie AVANT exécution : empreinte SHA-256 épinglée (si connue) et signature Authenticode (si exigée).
/// </summary>
public sealed class InstallerSource(ILog log, ProcessRunner runner)
{
    public static string DownloadDir => Path.Combine(SecureFiles.ProgramDataRoot, "downloads");

    public string Acquire(InstallerEntry entry, string? localPath, string? overrideSha256 = null)
    {
        ArgumentNullException.ThrowIfNull(entry);
        string path;
        if (!string.IsNullOrWhiteSpace(localPath))
        {
            path = Path.GetFullPath(localPath);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"Installeur introuvable : {path}");
            }

            log.Info($"{entry.DisplayName} : fichier local {path} (mode hors ligne).");
        }
        else
        {
            if (string.IsNullOrWhiteSpace(entry.Url))
            {
                throw new InstallerVerificationException(
                    $"{entry.DisplayName} : aucune URL officielle connue dans cette version. Fournissez l'installeur téléchargé depuis le site officiel (option hors ligne).");
            }

            path = Download(entry);
        }

        if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            // Archive : empreinte épinglée obligatoire, puis signature exigée sur le MSI extrait.
            VerifyHash(entry, path, overrideSha256, required: true);
            var msi = ExtractMsi(entry, path);
            VerifySignature(entry, msi, hashPinned: true);
            return msi;
        }

        Verify(entry, path, overrideSha256);
        return path;
    }

    /// <summary>
    /// Certains éditeurs (multiOTP) publient le MSI dans une archive zip : l'archive est vérifiée (empreinte épinglée),
    /// puis le MSI x64 est extrait dans un dossier protégé.
    /// </summary>
    private string ExtractMsi(InstallerEntry entry, string zipPath)
    {
        var dir = Path.Combine(DownloadDir, Path.GetFileNameWithoutExtension(zipPath));
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }

        SecureFiles.EnsureProtectedDirectory(dir);
        System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, dir);
        var msis = Directory.GetFiles(dir, "*.msi", SearchOption.AllDirectories);
        var msi = msis.FirstOrDefault(m => Path.GetFileName(m).Contains("x64", StringComparison.OrdinalIgnoreCase))
                  ?? (msis.Length == 1 ? msis[0] : throw new InstallerVerificationException($"{entry.DisplayName} : MSI x64 introuvable dans l'archive."));
        var sig = Authenticode.Verify(msi);
        log.Info($"{entry.DisplayName} : MSI extrait {Path.GetFileName(msi)}, sha256:{FileHash.Sha256Hex(msi)}, {sig}");
        return msi;
    }

    public void Verify(InstallerEntry entry, string path, string? overrideSha256 = null)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var hashPinned = VerifyHash(entry, path, overrideSha256, required: false);
        VerifySignature(entry, path, hashPinned);
    }

    private bool VerifyHash(InstallerEntry entry, string path, string? overrideSha256, bool required)
    {
        var expected = !string.IsNullOrWhiteSpace(overrideSha256) ? overrideSha256 : entry.Sha256;
        var actual = FileHash.Sha256Hex(path);
        log.Info($"{entry.DisplayName} : empreinte sha256:{actual}");
        var hashPinned = !string.IsNullOrWhiteSpace(expected);
        if (hashPinned && !string.Equals(actual, expected!.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallerVerificationException($"{entry.DisplayName} : empreinte SHA-256 inattendue. Fichier refusé (attendu sha256:{expected}).");
        }

        if (required && !hashPinned)
        {
            throw new InstallerVerificationException($"{entry.DisplayName} : archive sans empreinte épinglée. Indiquez l'empreinte SHA-256 publiée par l'éditeur (--sha256), ou fournissez directement le MSI.");
        }

        return hashPinned;
    }

    private void VerifySignature(InstallerEntry entry, string path, bool hashPinned)
    {
        var signed = Authenticode.IsTrusted(path, entry.SignerSubjectContains, out var sig);
        log.Info($"{entry.DisplayName} : {sig}");
        if (entry.RequireAuthenticode && !signed)
        {
            throw new InstallerVerificationException($"{entry.DisplayName} : signature Authenticode absente, invalide ou d'un éditeur inattendu ({sig}). Fichier refusé.");
        }

        if (!hashPinned && !signed)
        {
            throw new InstallerVerificationException(
                $"{entry.DisplayName} : ni empreinte épinglée ni signature valide. Indiquez l'empreinte SHA-256 publiée par l'éditeur (option --sha256) après l'avoir vérifiée.");
        }
    }

    private string Download(InstallerEntry entry)
    {
        SecureFiles.EnsureProtectedDirectory(DownloadDir);
        var name = Path.GetFileName(new Uri(entry.Url).AbsolutePath);
        if (string.IsNullOrEmpty(name) || !name.Contains('.', StringComparison.Ordinal))
        {
            name = string.Create(CultureInfo.InvariantCulture, $"{entry.DisplayName.GetHashCode(StringComparison.Ordinal):X8}.exe");
        }

        var path = Path.Combine(DownloadDir, name);
        log.Info($"Téléchargement de {entry.DisplayName} depuis {entry.Url}…");
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("SecureDesk");
        using var response = http.GetAsync(new Uri(entry.Url), HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
        {
            throw new InstallerVerificationException("Téléchargement refusé : redirection hors HTTPS.");
        }

        using (var fs = File.Create(path))
        {
            response.Content.CopyToAsync(fs).GetAwaiter().GetResult();
        }

        return path;
    }

    /// <summary>msiexec /i silencieux. 3010 = succès, redémarrage requis.</summary>
    public bool InstallMsi(string msiPath, IEnumerable<string> properties, string logName, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(properties);
        SecureFiles.EnsureProtectedDirectory(SecureFiles.LogsDir);
        var msiLog = Path.Combine(SecureFiles.LogsDir, logName);
        var args = new List<string> { "/i", msiPath, "/qn", "/norestart" };
        args.AddRange(properties);
        args.Add("/l*v");
        args.Add(msiLog);
        var r = runner.RunChecked(ProcessRunner.SystemExe("msiexec.exe"), args, timeout: timeout ?? TimeSpan.FromMinutes(15), okCodes: [0, 3010, 1641]);
        if (r.ExitCode != 0)
        {
            log.Warn("L'installation demande un redémarrage de Windows.");
        }

        return r.ExitCode != 0;
    }

    public void UninstallMsiByProductCode(string productCode, string logName)
    {
        SecureFiles.EnsureProtectedDirectory(SecureFiles.LogsDir);
        var msiLog = Path.Combine(SecureFiles.LogsDir, logName);
        runner.RunChecked(ProcessRunner.SystemExe("msiexec.exe"), ["/x", productCode, "/qn", "/norestart", "/l*v", msiLog],
            timeout: TimeSpan.FromMinutes(15), okCodes: [0, 3010, 1605, 1641]);
    }
}

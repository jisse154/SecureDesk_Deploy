using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SecureDesk.Windows.Sys;

/// <summary>ACL protégées (sans héritage) : SYSTEM et Administrateurs uniquement, contrôle total.</summary>
public static class SecureFiles
{
    public static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    public static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static string ProgramDataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureDesk");

    public static string LogsDir => Path.Combine(ProgramDataRoot, "logs");
    public static string WireGuardDir => Path.Combine(ProgramDataRoot, "wireguard");
    public static string SecretsDir => Path.Combine(ProgramDataRoot, "secrets");
    public static string StatePath => Path.Combine(ProgramDataRoot, "state.json");

    public static DirectorySecurity ProtectedDirectorySecurity()
    {
        var ds = new DirectorySecurity();
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.SetOwner(Administrators);
        foreach (var sid in new[] { System, Administrators })
        {
            ds.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }

        return ds;
    }

    public static FileSecurity ProtectedFileSecurity()
    {
        var fs = new FileSecurity();
        fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        fs.SetOwner(Administrators);
        foreach (var sid in new[] { System, Administrators })
        {
            fs.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        return fs;
    }

    /// <summary>Crée (ou corrige) un répertoire protégé.</summary>
    public static void EnsureProtectedDirectory(string path)
    {
        var di = new DirectoryInfo(path);
        if (!di.Exists)
        {
            di.Create(ProtectedDirectorySecurity());
        }

        di.SetAccessControl(ProtectedDirectorySecurity());
    }

    /// <summary>
    /// Écrit un fichier sensible : le fichier est créé VIDE avec l'ACL protégée, puis rempli, pour qu'il n'existe
    /// jamais d'instant où le contenu serait lisible avec une ACL héritée.
    /// </summary>
    public static void WriteProtected(string path, string content, Encoding? encoding = null)
    {
        var dir = Path.GetDirectoryName(path)!;
        EnsureProtectedDirectory(dir);
        var tmp = path + ".tmp";
        var fi = new FileInfo(tmp);
        using (var fs = fi.Create(FileMode.Create, FileSystemRights.Write | FileSystemRights.ReadData, FileShare.None, 4096, FileOptions.None, ProtectedFileSecurity()))
        using (var w = new StreamWriter(fs, encoding ?? new UTF8Encoding(false)))
        {
            w.Write(content);
        }

        File.Move(tmp, path, overwrite: true);
        new FileInfo(path).SetAccessControl(ProtectedFileSecurity());
    }

    /// <summary>Vrai si seuls SYSTEM et Administrateurs ont un accès, et si l'héritage est coupé.</summary>
    public static bool IsProtected(string path)
    {
        FileSystemSecurity sec = Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();
        if (!sec.AreAccessRulesProtected)
        {
            return false;
        }

        foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (rule.AccessControlType == AccessControlType.Allow && sid != System && sid != Administrators)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Retire tout accès en lecture au groupe Utilisateurs et Utilisateurs authentifiés sur un répertoire existant.</summary>
    public static void RevokeUsers(string path)
    {
        var di = new DirectoryInfo(path);
        var sec = di.GetAccessControl();
        sec.SetAccessRuleProtection(true, true);
        di.SetAccessControl(sec);
        sec = di.GetAccessControl();
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), new SecurityIdentifier(WellKnownSidType.WorldSid, null) })
        {
            sec.PurgeAccessRules(sid);
        }

        di.SetAccessControl(sec);
    }

    /// <summary>
    /// Suppression « au mieux » : écrasement du contenu puis suppression.
    /// Sur SSD/flash l'écrasement n'est pas garanti (répartition d'usure) : l'utilisateur en est averti.
    /// </summary>
    public static void BestEffortWipe(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var len = new FileInfo(path).Length;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            var zero = new byte[8192];
            for (long done = 0; done < len; done += zero.Length)
            {
                fs.Write(zero, 0, (int)Math.Min(zero.Length, len - done));
            }

            fs.Flush(true);
        }

        File.Delete(path);
    }
}

using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using SecureDesk.Core.Hardening;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Security;

namespace SecureDesk.Windows.Sys;

public sealed record LocalAccountInfo(string Name, bool Enabled, bool LockedOut, bool HasPassword, bool IsAdministrator, bool IsRemoteDesktopUser);

/// <summary>Comptes locaux et groupes, identifiés par SID (indépendant de la langue de Windows).</summary>
public sealed class Accounts(ILog log)
{
    private static PrincipalContext Machine() => new(ContextType.Machine);

    public static bool Exists(string name)
    {
        using var ctx = Machine();
        using var u = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, name);
        return u is not null;
    }

    public static LocalAccountInfo? Get(string name)
    {
        using var ctx = Machine();
        using var u = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, name);
        if (u is null)
        {
            return null;
        }

        return new LocalAccountInfo(
            u.SamAccountName,
            u.Enabled ?? false,
            u.IsAccountLockedOut(),
            !u.PasswordNotRequired,
            IsMember(ctx, u, HardeningPlan.AdministratorsSid),
            IsMember(ctx, u, HardeningPlan.RemoteDesktopUsersSid));
    }

    public static IReadOnlyList<LocalAccountInfo> Administrators() => Members(HardeningPlan.AdministratorsSid);

    public static IReadOnlyList<LocalAccountInfo> Members(string groupSid)
    {
        using var ctx = Machine();
        using var g = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, groupSid);
        if (g is null)
        {
            return [];
        }

        var result = new List<LocalAccountInfo>();
        foreach (var m in g.GetMembers(recursive: false))
        {
            using (m)
            {
                if (m is UserPrincipal up && up.Context.ContextType == ContextType.Machine)
                {
                    var info = Get(up.SamAccountName);
                    if (info is not null)
                    {
                        result.Add(info);
                    }
                }
            }
        }

        return result;
    }

    public void Create(string name, SensitiveText password, string? fullName)
    {
        ArgumentNullException.ThrowIfNull(password);
        using var ctx = Machine();
        using var u = new UserPrincipal(ctx, name, password.Reveal(), enabled: true)
        {
            DisplayName = fullName ?? name,
            Description = "Compte créé par SecureDesk",
            PasswordNeverExpires = false,
            UserCannotChangePassword = false,
        };
        u.Save();
        log.Info($"Compte local créé : {name}");
    }

    public void AddToGroup(string name, string groupSid)
    {
        using var ctx = Machine();
        using var g = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, groupSid) ?? throw new InvalidOperationException($"Groupe {groupSid} introuvable.");
        using var u = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, name) ?? throw new InvalidOperationException($"Compte {name} introuvable.");
        if (!u.IsMemberOf(g))
        {
            g.Members.Add(u);
            g.Save();
            log.Info($"{name} ajouté au groupe {g.Name}.");
        }
    }

    public static bool IsInGroup(string name, string groupSid)
    {
        using var ctx = Machine();
        using var u = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, name);
        return u is not null && IsMember(ctx, u, groupSid);
    }

    private static bool IsMember(PrincipalContext ctx, UserPrincipal u, string groupSid)
    {
        using var g = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, groupSid);
        return g is not null && u.IsMemberOf(g);
    }

    public static string CurrentUserName()
    {
        using var id = WindowsIdentity.GetCurrent();
        var n = id.Name;
        var slash = n.LastIndexOf('\\');
        return slash >= 0 ? n[(slash + 1)..] : n;
    }

    /// <summary>Contrôle de robustesse avant création (Windows appliquera aussi sa propre stratégie).</summary>
    public static IReadOnlyList<string> CheckPassword(SensitiveText password, string accountName, int minLength)
    {
        ArgumentNullException.ThrowIfNull(password);
        var p = password.Reveal();
        var problems = new List<string>();
        if (p.Length < minLength)
        {
            problems.Add($"au moins {minLength} caractères");
        }

        var classes = new[] { p.Any(char.IsUpper), p.Any(char.IsLower), p.Any(char.IsDigit), p.Any(c => !char.IsLetterOrDigit(c)) }.Count(b => b);
        if (classes < 3)
        {
            problems.Add("au moins 3 types parmi majuscules, minuscules, chiffres, symboles");
        }

        if (!string.IsNullOrEmpty(accountName) && p.Contains(accountName, StringComparison.OrdinalIgnoreCase))
        {
            problems.Add("ne doit pas contenir le nom du compte");
        }

        return problems;
    }
}

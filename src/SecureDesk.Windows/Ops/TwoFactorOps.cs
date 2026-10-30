using System.Globalization;
using SecureDesk.Core.Config;
using SecureDesk.Core.Hardening;
using SecureDesk.Core.Logging;
using SecureDesk.Core.MultiOtp;
using SecureDesk.Core.State;
using SecureDesk.Core.Time;
using SecureDesk.Windows.MultiOtp;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.Ops;

/// <summary>
/// Double authentification multiOTP avec garde-fous anti-verrouillage :
/// installation DÉSACTIVÉE, enrôlement vérifié, activation probatoire, désactivation propre.
/// </summary>
public sealed class TwoFactorOps(Context ctx)
{
    private readonly MultiOtpOps _otp = new(ctx.Log, ctx.Runner);
    private TwoFactorState T => ctx.State.TwoFactor;

    public void Install()
    {
        RequireServerReady();
        if (MultiOtpOps.Status().Installed)
        {
            ctx.Ui.Info("multiOTP Credential Provider déjà installé : vérification.");
            if (!ctx.DryRun)
            {
                _otp.VerifyInstalled();
                T.Installed = true;
                ctx.Save();
            }

            return;
        }

        if (ctx.DryRun)
        {
            ctx.Ui.Info("[à faire] Installer VC++ 2015-2022 x64 puis le MSI multiOTP CP en mode local, DÉSACTIVÉ (cpus_* = 3d).");
            return;
        }

        new SelfInstall(ctx.Log, ctx.Runner).EnsureInstalled();
        _otp.Install(ctx.Manifest, ctx.Config.Installers.MultiOtpMsi, ctx.Config.Installers.VcRedist, ctx.Sha256Override);
        ctx.State.RecordOriginal("installed:multiotp", "installed", new Dictionary<string, string?> { ["product"] = "multiOTP Credential Provider" });
        T.Installed = true;
        T.Active = false;
        ctx.Save();
    }

    /// <summary>Enrôle un compte : QR affiché une fois, validation par un premier code, codes de secours.</summary>
    public void Enroll(string account)
    {
        if (!MultiOtpOps.Status().Installed)
        {
            throw new OperationException("multiOTP n'est pas installé : lancez d'abord « install-2fa ».");
        }

        var info = Sys.Accounts.Get(account) ?? throw new OperationException($"Compte Windows « {account} » introuvable sur ce PC.");
        if (ctx.DryRun)
        {
            ctx.Ui.Info($"[à faire] Enrôler « {account} » : QR code, vérification d'un code, codes de secours.");
            return;
        }

        var drift = Checks.Clock(ctx.Config.Server.NtpServer);
        if (drift.Level == CheckLevel.Blocking)
        {
            throw new OperationException(drift.Detail + ". Corrigez l'heure (harden configure W32Time) avant l'enrôlement.");
        }

        if (_otp.UserExists(account))
        {
            if (!ctx.Ui.Confirm($"« {account} » a déjà un jeton multiOTP. Le remplacer (l'ancien code dans l'application ne fonctionnera plus) ?"))
            {
                return;
            }

            _otp.DeleteUser(account);
        }

        _otp.CreateUser(account);
        var verified = false;
        try
        {
            var (uri, qrText) = _otp.ProvisioningUri(account);
            ctx.Ui.ShowQrOnce($"Scannez ce QR code avec votre application d'authentification (compte « {account} »)", qrText);
            for (var attempt = 1; attempt <= 3 && !verified; attempt++)
            {
                var code = ctx.Ui.Ask(string.Create(CultureInfo.InvariantCulture, $"Code à {uri.Digits} chiffres affiché par l'application (essai {attempt}/3)")).Trim();
                var rc = _otp.CheckCode(account, code);
                if (rc == MultiOtpExitCodes.TokenAccepted)
                {
                    verified = true;
                }
                else
                {
                    ctx.Ui.Warn("Code refusé : " + MultiOtpExitCodes.Describe(rc));
                }
            }

            if (!verified)
            {
                throw new OperationException("Enrôlement non validé : le jeton est supprimé. Vérifiez l'heure du téléphone et recommencez.");
            }

            var codes = _otp.ScratchList(account);
            ctx.Ui.ShowSecretsOnce($"Codes de secours à usage unique pour « {account} » — imprimez-les ou notez-les sur papier, conservez-les hors du PC",
                [MultiOtpOps.FormatCodes(codes), "Chaque code remplace UNE fois le code de l'application (téléphone perdu)."]);
        }
        finally
        {
            if (!verified)
            {
                _otp.DeleteUser(account);
            }
        }

        T.Users.RemoveAll(u => u.Name.Equals(account, StringComparison.OrdinalIgnoreCase));
        T.Users.Add(new EnrolledUser { Name = account, IsAdministrator = info.IsAdministrator, VerifiedUtc = ctx.Clock.GetUtcNow() });
        ctx.Save();
        ctx.Ui.Info($"« {account} » enrôlé et vérifié. Attendez le code SUIVANT pour la première connexion (un code ne sert qu'une fois).");
    }

    /// <summary>Liste des garde-fous ; vide = activation autorisée.</summary>
    public IReadOnlyList<string> Guards(TwoFactorScope scope)
    {
        var problems = new List<string>();
        var st = MultiOtpOps.Status();
        if (!st.Installed)
        {
            problems.Add("multiOTP n'est pas installé (install-2fa).");
            return problems;
        }

        if (!st.DllSigned)
        {
            problems.Add("La DLL du Credential Provider n'a pas de signature valide.");
        }

        if (SystemInfo.IsRemoteSession() && !ctx.ConsoleAccessAcknowledged)
        {
            problems.Add("SecureDesk est lancé depuis une session À DISTANCE : activez le 2FA depuis la console du PC, ou ajoutez --i-have-console-access si quelqu'un peut intervenir physiquement.");
        }

        var enrolledAdmins = T.Users.Where(u => u.IsAdministrator && Sys.Accounts.IsInGroup(u.Name, HardeningPlan.AdministratorsSid)).ToList();
        if (enrolledAdmins.Count == 0)
        {
            problems.Add("Aucun compte ADMINISTRATEUR n'est enrôlé et vérifié (enroll-user <compte admin>).");
        }

        var enrolled = T.Users.Select(u => u.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var mustBeEnrolled = ctx.Config.TwoFactorAccounts()
            .Concat(Sys.Accounts.Members(HardeningPlan.RemoteDesktopUsersSid).Select(a => a.Name))
            .Where(n => Sys.Accounts.Get(n) is { Enabled: true })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(n => !enrolled.Contains(n))
            .ToList();
        if (mustBeEnrolled.Count > 0)
        {
            problems.Add("Comptes autorisés en RDP mais non enrôlés (ils seraient bloqués) : " + string.Join(", ", mustBeEnrolled) + ".");
        }

        if (scope == TwoFactorScope.RemoteOnly)
        {
            var consoleAdmin = Sys.Accounts.Administrators().Any(a => a.Enabled && !a.LockedOut && a.HasPassword);
            if (!consoleAdmin)
            {
                problems.Add("Aucun administrateur local actif avec mot de passe : l'accès console de secours n'est pas garanti.");
            }
        }

        try
        {
            var offset = Sntp.MeasureOffsetAsync(ctx.Config.Server.NtpServer, TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
            if (Math.Abs(offset.TotalSeconds) > Sntp.MaxAllowedDrift.TotalSeconds)
            {
                problems.Add(string.Create(CultureInfo.InvariantCulture, $"Dérive d'horloge de {offset.TotalSeconds:0.0} s (> 30 s)."));
            }
        }
#pragma warning disable CA1031
        catch (Exception)
#pragma warning restore CA1031
        {
            ctx.Ui.Warn("Mesure de l'horloge impossible (réseau) : vérifiez manuellement l'heure de Windows.");
        }

        if (!File.Exists(SelfInstall.Exe))
        {
            problems.Add($"{SelfInstall.Exe} est absent : disable-2fa ne serait pas disponible à la console.");
        }

        return problems;
    }

    /// <summary>Activation probatoire : sans confirm-2fa avant l'échéance, une tâche SYSTEM désactive le 2FA.</summary>
    public void Enable(TwoFactorScope scope)
    {
        var problems = Guards(scope);
        if (problems.Count > 0)
        {
            throw new OperationException("Activation du 2FA REFUSÉE (protection anti-verrouillage) :\n - " + string.Join("\n - ", problems));
        }

        var minutes = ctx.Config.Server.TwoFactor.ProbationMinutes;
        var deadline = ctx.Clock.GetUtcNow().AddMinutes(minutes);
        ctx.Ui.Show("Activation du 2FA",
        [
            "Portée : " + MultiOtpOps.DescribeScope(scope),
            string.Create(CultureInfo.InvariantCulture, $"Activation PROBATOIRE : sans « SecureDesk.exe confirm-2fa » d'ici {minutes} min, le 2FA se désactivera tout seul."),
            "Testez maintenant depuis le PC client : connexion RDP via le tunnel, mot de passe puis code TOTP.",
            "En cas de problème à la console : SecureDesk.exe disable-2fa (voir README, récupération).",
        ]);
        if (ctx.DryRun)
        {
            ctx.Ui.Info("[à faire] Tâche de désactivation automatique, puis cpus_logon/cpus_unlock = " + MultiOtpPlan.ActivationValues(scope)["cpus_logon"]);
            return;
        }

        if (!ctx.Ui.Confirm("Activer le 2FA maintenant ?"))
        {
            return;
        }

        var self = new SelfInstall(ctx.Log, ctx.Runner);
        // La tâche de secours est créée AVANT l'activation.
        self.ScheduleProbation(deadline);
        try
        {
            _otp.SetActive(scope, ctx.State);
        }
        catch
        {
            _otp.SetDisabled();
            self.CancelProbation();
            throw;
        }

        T.Active = true;
        T.Scope = scope;
        T.Confirmed = false;
        T.ProbationDeadlineUtc = deadline;
        ctx.Save();
        ctx.Ui.Info($"2FA ACTIF ({MultiOtpOps.DescribeScope(scope)}). Échéance probatoire : {deadline.ToLocalTime():HH:mm}.");
    }

    public void Confirm()
    {
        if (!T.Active || !MultiOtpOps.Status().Active)
        {
            throw new OperationException("Le 2FA n'est pas actif : rien à confirmer.");
        }

        if (ctx.DryRun)
        {
            ctx.Ui.Info("[à faire] Supprimer la tâche de désactivation automatique.");
            return;
        }

        new SelfInstall(ctx.Log, ctx.Runner).CancelProbation();
        T.Confirmed = true;
        T.ProbationDeadlineUtc = null;
        ctx.Save();
        ctx.Ui.Info("2FA confirmé : il reste actif de façon permanente.");
    }

    /// <summary>Désactivation propre (cpus_* = 3d). Le Credential Provider reste installé, les enrôlements sont conservés.</summary>
    public void Disable(bool fromProbation)
    {
        if (ctx.DryRun)
        {
            ctx.Ui.Info("[à faire] cpus_logon/cpus_unlock/cpus_credui = 3d.");
            return;
        }

        _otp.SetDisabled();
        if (fromProbation)
        {
            ctx.Log.Warn("Désactivation automatique du 2FA : confirm-2fa n'a pas été exécuté dans le délai probatoire.");
        }

        try
        {
            new SelfInstall(ctx.Log, ctx.Runner).CancelProbation();
        }
        catch (ProcessFailedException ex)
        {
            ctx.Log.Warn("Suppression de la tâche probatoire impossible : " + ex.Message);
        }

        T.Active = false;
        T.Confirmed = false;
        T.ProbationDeadlineUtc = null;
        ctx.Save();
        ctx.Ui.Info("2FA désactivé : les connexions ne demandent plus de code TOTP (mot de passe Windows seul).");
    }

    private void RequireServerReady()
    {
        if (ctx.State.Role != "server" || ctx.State.Server?.Peers.Count is null or 0)
        {
            ctx.Ui.Warn("Recommandation du plan : installez le 2FA une fois le tunnel et la connexion RDP validés (au moins un pair appairé).");
            if (!ctx.Ui.Confirm("Continuer quand même ?"))
            {
                throw new OperationException("Installation du 2FA reportée.");
            }
        }
    }
}

using SecureDesk.Core.Config;

namespace SecureDesk.Core.MultiOtp;

/// <summary>
/// Paramètres du multiOTP Credential Provider, tirés EXCLUSIVEMENT de la documentation et des sources officielles :
/// github.com/multiOTP/multiOTPCredentialProvider (README « TECHNICAL DETAILS », WixInstall/…/Product.wxs, Shared/Shared.cpp).
/// </summary>
public static class MultiOtpPlan
{
    /// <summary>CLSID du Credential Provider (README : options stockées sous HKCR\CLSID\{…}).</summary>
    public const string ClsId = "{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}";

    /// <summary>Clé de registre des options, relative à HKEY_CLASSES_ROOT.</summary>
    public const string RegistryKey = @"CLSID\" + ClsId;

    /// <summary>« 3 : … multiOTP Credential Provider is completely disabled » (README), « d » : autres fournisseurs disponibles.</summary>
    public const string Disabled = "3d";

    /// <summary>
    /// « 1 : relevant for remote operation », « e : Only the multiOTP Credential Provider is available ».
    /// D'après Shared.cpp, le filtre ne masque les autres fournisseurs que si la session est distante :
    /// la console reste inchangée. « 1d » laisserait le fournisseur mot de passe standard en RDP = contournement du TOTP.
    /// </summary>
    public const string RemoteOnlyEnforced = "1e";

    /// <summary>« 0 : relevant for remote (RDP) and local operation » + « e ».</summary>
    public const string RemoteAndLocalEnforced = "0e";

    public static readonly IReadOnlyList<string> ScenarioValueNames = ["cpus_logon", "cpus_unlock", "cpus_credui"];

    /// <summary>Valeurs à écrire à l'activation. CredUI (UAC) reste désactivé pour ne pas casser l'élévation.</summary>
    public static IReadOnlyDictionary<string, string> ActivationValues(TwoFactorScope scope)
    {
        var v = scope == TwoFactorScope.RemoteAndLocal ? RemoteAndLocalEnforced : RemoteOnlyEnforced;
        return new Dictionary<string, string>
        {
            ["cpus_logon"] = v,
            ["cpus_unlock"] = v,
            ["cpus_credui"] = Disabled,
        };
    }

    public static IReadOnlyDictionary<string, string> DisabledValues() =>
        ScenarioValueNames.ToDictionary(n => n, _ => Disabled);

    /// <summary>
    /// Valeurs de registre qui doivent être présentes après installation (contrôle post-install, car le README avertit :
    /// « Silent install supported (WARNING! No test will be done, be sure the registry parameters are correct!) »).
    /// </summary>
    public static IReadOnlyDictionary<string, string> ExpectedAfterInstall() => new Dictionary<string, string>
    {
        ["cpus_logon"] = Disabled,
        ["cpus_unlock"] = Disabled,
        ["cpus_credui"] = Disabled,
        ["multiOTPServers"] = string.Empty,
        ["two_step_hide_otp"] = "1",
        ["excluded_account"] = string.Empty,
        ["included_providers_id"] = string.Empty,
    };

    /// <summary>
    /// Arguments msiexec (propriétés publiques déclarées dans Product.wxs).
    /// MULTIOTP_URL vide = aucun serveur distant : multiOTP embarqué, authentification locale.
    /// </summary>
    public static IReadOnlyList<string> MsiProperties() =>
    [
        "MULTIOTP_URL=\"\"",
        "MULTIOTP_SECRET=\"\"",
        "MULTIOTP_CACHE=0",
        "MULTIOTP_LOCALSERVERONLY=1",
        "CPUS_LOGON=" + Disabled,
        "CPUS_UNLOCK=" + Disabled,
        "CPUS_CREDUI=" + Disabled,
        "MULTIOTP_TWO_STEP_HIDE_OTP=1",
        "MULTIOTP_DISPLAYSMSLINK=0",
        "MULTIOTP_DISPLAYEMAILLINK=0",
        "MULTIOTP_WITHOUT2FA=0",
        "MULTIOTP_EXCLUDED_ACCOUNT=\"\"",
    ];

    /// <summary>Le scénario d'ouverture de session est-il protégé par le CP d'après la valeur cpus_logon ?</summary>
    public static bool IsActive(string? cpusLogon) =>
        !string.IsNullOrEmpty(cpusLogon) && cpusLogon[0] is '0' or '1' or '2';
}

/// <summary>Codes de retour de la CLI multiotp (aide « multiotp -error-codes », readme.md).</summary>
public static class MultiOtpExitCodes
{
    public const int TokenAccepted = 0;
    public const int UserCreated = 11;
    public const int UserDeleted = 12;
    public const int UrlLinkCreated = 17;
    public const int OperationDone = 19;
    public const int UserDoesNotExist = 21;
    public const int UserAlreadyExists = 22;
    public const int UserLocked = 24;
    public const int UserDelayed = 25;
    public const int TokenAlreadyUsed = 26;
    public const int AuthenticationFailed = 99;

    public static string Describe(int code) => code switch
    {
        0 => "code accepté",
        11 => "utilisateur créé ou mis à jour",
        12 => "utilisateur supprimé",
        17 => "lien de provisionnement généré",
        19 => "opération effectuée",
        21 => "utilisateur inconnu de multiOTP",
        22 => "utilisateur déjà existant",
        24 => "utilisateur verrouillé (trop d'essais)",
        25 => "utilisateur temporisé (trop d'essais, réessayez dans quelques minutes)",
        26 => "ce code a déjà été utilisé : attendez le suivant",
        99 => "authentification refusée",
        _ => $"code {code}",
    };
}

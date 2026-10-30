using System.Globalization;
using System.Text.RegularExpressions;

namespace SecureDesk.Core.Logging;

/// <summary>
/// Dernier filet de sécurité avant toute écriture (log, rapport, console) : masque ce qui ressemble à un secret.
/// Les secrets ne doivent de toute façon jamais être passés au logger (types <c>SensitiveText</c>/<c>WgSecretKey</c>).
/// </summary>
public static partial class Redactor
{
    public const string Mask = "[MASQUÉ]";

    // Clé WireGuard (privée, publique ou PSK) : 43 caractères base64 + '='.
    [GeneratedRegex(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])", RegexOptions.CultureInvariant)]
    private static partial Regex WgKey();

    // URI de provisionnement TOTP/HOTP.
    [GeneratedRegex(@"otpauth://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OtpAuth();

    // Paramètre secret=... (URI, lignes de commande).
    [GeneratedRegex(@"(?i)(secret|seed|token_seed|psk|password|passphrase|mot_de_passe)\s*[=:]\s*\S+", RegexOptions.CultureInvariant)]
    private static partial Regex KeyValueSecret();

    // Lignes de configuration WireGuard sensibles.
    [GeneratedRegex(@"(?im)^(\s*(PrivateKey|PresharedKey)\s*=\s*).*$", RegexOptions.CultureInvariant)]
    private static partial Regex WgConfigSecret();

    // Graine base32 longue (≥ 16 caractères), typique des seeds TOTP.
    [GeneratedRegex(@"(?<![A-Z2-7])[A-Z2-7]{16,}={0,6}(?![A-Z2-7])", RegexOptions.CultureInvariant)]
    private static partial Regex Base32Seed();

    // Graine hexadécimale longue (≥ 32 caractères), format interne multiOTP.
    [GeneratedRegex(@"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])", RegexOptions.CultureInvariant)]
    private static partial Regex HexSeed();

    // Empreinte publique d'un installeur : à conserver lisible dans les journaux.
    [GeneratedRegex(@"sha256:[0-9a-fA-F]{64}(?![0-9a-fA-F])", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Hash();

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var hashes = new List<string>();
        var r = Sha256Hash().Replace(text, m =>
        {
            hashes.Add(m.Value);
            return "\u0001" + (hashes.Count - 1).ToString(CultureInfo.InvariantCulture) + "\u0001";
        });
        r = WgConfigSecret().Replace(r, m => m.Groups[1].Value + Mask);
        r = OtpAuth().Replace(r, Mask);
        r = KeyValueSecret().Replace(r, m => m.Groups[1].Value + "=" + Mask);
        r = WgKey().Replace(r, Mask);
        r = Base32Seed().Replace(r, Mask);
        r = HexSeed().Replace(r, Mask);
        for (var i = 0; i < hashes.Count; i++)
        {
            r = r.Replace("\u0001" + i.ToString(CultureInfo.InvariantCulture) + "\u0001", hashes[i], StringComparison.Ordinal);
        }

        return r;
    }
}

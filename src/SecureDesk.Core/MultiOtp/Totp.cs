using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SecureDesk.Core.MultiOtp;

/// <summary>
/// TOTP (RFC 6238, HMAC-SHA1). SecureDesk ne valide jamais lui-même les codes en production (c'est multiOTP qui le fait) :
/// ce calcul sert aux tests d'intégration et à la vérification de cohérence de l'URI de provisionnement.
/// </summary>
public static class Totp
{
    public static string Compute(byte[] secret, DateTimeOffset time, int digits = 6, int period = 30)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var counter = (ulong)(time.ToUnixTimeSeconds() / period);
        Span<byte> msg = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(msg, counter);
#pragma warning disable CA5350 // HMAC-SHA1 imposé par RFC 6238 / applications Authenticator.
        var hash = HMACSHA1.HashData(secret, msg);
#pragma warning restore CA5350
        var offset = hash[^1] & 0x0F;
        var bin = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        var mod = (int)Math.Pow(10, digits);
        return (bin % mod).ToString(new string('0', digits), CultureInfo.InvariantCulture);
    }

    public static byte[] Base32Decode(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var clean = input.Trim().TrimEnd('=').Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
        var output = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var c in clean)
        {
            var v = alphabet.IndexOf(c, StringComparison.Ordinal);
            if (v < 0)
            {
                throw new FormatException("Caractère base32 invalide.");
            }

            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }

        return [.. output];
    }

    public static string Base32Encode(ReadOnlySpan<byte> data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            sb.Append(alphabet[(buffer << (5 - bits)) & 31]);
        }

        return sb.ToString();
    }
}

/// <summary>URI otpauth:// (format Key Uri de Google Authenticator). Contient la graine : ne jamais journaliser.</summary>
public sealed class OtpAuthUri
{
    private OtpAuthUri(string type, string label, string secretBase32, int digits, int period)
    {
        Type = type;
        Label = label;
        SecretBase32 = secretBase32;
        Digits = digits;
        Period = period;
    }

    public string Type { get; }
    public string Label { get; }
    internal string SecretBase32 { get; }
    public int Digits { get; }
    public int Period { get; }

    public override string ToString() => $"otpauth://{Type}/{Label} (graine masquée)";

    public static bool TryParse(string? text, out OtpAuthUri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var start = text.IndexOf("otpauth://", StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return false;
        }

        var end = start;
        while (end < text.Length && !char.IsWhiteSpace(text[end]))
        {
            end++;
        }

        if (!Uri.TryCreate(text[start..end], UriKind.Absolute, out var u))
        {
            return false;
        }

        var query = u.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .Where(p => p.Length == 2)
            .GroupBy(p => p[0].ToLowerInvariant())
            .ToDictionary(g => g.Key, g => Uri.UnescapeDataString(g.First()[1]), StringComparer.Ordinal);
        if (!query.TryGetValue("secret", out var secret) || secret.Length < 16)
        {
            return false;
        }

        var digits = query.TryGetValue("digits", out var d) && int.TryParse(d, NumberStyles.None, CultureInfo.InvariantCulture, out var dd) ? dd : 6;
        var period = query.TryGetValue("period", out var p) && int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var pp) ? pp : 30;
        uri = new OtpAuthUri(u.Host.ToLowerInvariant(), Uri.UnescapeDataString(u.AbsolutePath.TrimStart('/')), secret, digits, period);
        return true;
    }

    /// <summary>Texte complet à encoder dans le QR code (contient la graine).</summary>
    public string ToProvisioningText(string originalText)
    {
        ArgumentNullException.ThrowIfNull(originalText);
        var start = originalText.IndexOf("otpauth://", StringComparison.OrdinalIgnoreCase);
        var end = start;
        while (end < originalText.Length && !char.IsWhiteSpace(originalText[end]))
        {
            end++;
        }

        return originalText[start..end];
    }

    public string CurrentCode(DateTimeOffset now) => Totp.Compute(Totp.Base32Decode(SecretBase32), now, Digits, Period);
}

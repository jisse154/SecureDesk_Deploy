using System.Security.Cryptography;
using System.Text;

namespace SecureDesk.Core.Security;

/// <summary>
/// Texte sensible (mot de passe, phrase de passe, graine…). <see cref="ToString"/> ne révèle jamais la valeur :
/// une interpolation accidentelle dans un log ou un rapport n'affiche que « *** ».
/// </summary>
public sealed class SensitiveText : IEquatable<SensitiveText>
{
    private readonly string _value;

    public SensitiveText(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
    }

    public int Length => _value.Length;
    public bool IsEmpty => _value.Length == 0;

    /// <summary>Accès explicite à la valeur. À n'utiliser qu'au point de consommation.</summary>
    public string Reveal() => _value;

    public byte[] RevealUtf8() => Encoding.UTF8.GetBytes(_value);

    public override string ToString() => "***";

    public bool Equals(SensitiveText? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(_value), Encoding.UTF8.GetBytes(other._value));

    public override bool Equals(object? obj) => obj is SensitiveText s && Equals(s);

    public override int GetHashCode() => 0;
}

/// <summary>Clé WireGuard (Curve25519) : 32 octets encodés en base64 (44 caractères).</summary>
public static class WgKeyFormat
{
    public static bool IsValid(string? key)
    {
        if (string.IsNullOrEmpty(key) || key.Length != 44 || key[43] != '=')
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[33];
        return Convert.TryFromBase64String(key, buffer, out var written) && written == 32;
    }

    public static void EnsureValid(string? key, string what)
    {
        if (!IsValid(key))
        {
            throw new FormatException($"{what} : clé WireGuard invalide (32 octets base64 attendus).");
        }
    }

    /// <summary>Empreinte courte, lisible à voix haute, d'une clé publique.</summary>
    public static string Fingerprint(string publicKey)
    {
        EnsureValid(publicKey, "Empreinte");
        var hash = SHA256.HashData(Convert.FromBase64String(publicKey));
        var hex = Convert.ToHexString(hash, 0, 8);
        return string.Join('-', Enumerable.Range(0, 4).Select(i => hex.Substring(i * 4, 4)));
    }
}

/// <summary>Clé publique WireGuard : non secrète.</summary>
public sealed record WgPublicKey
{
    public WgPublicKey(string value)
    {
        WgKeyFormat.EnsureValid(value, "Clé publique");
        Value = value;
    }

    public string Value { get; }
    public string Fingerprint => WgKeyFormat.Fingerprint(Value);
    public override string ToString() => Value;
}

/// <summary>Clé secrète WireGuard (privée ou pré-partagée). Jamais affichée.</summary>
public sealed class WgSecretKey
{
    private readonly string _value;

    public WgSecretKey(string value)
    {
        WgKeyFormat.EnsureValid(value, "Clé secrète");
        _value = value;
    }

    public string Reveal() => _value;

    public override string ToString() => "(secret)";

    public override bool Equals(object? obj) =>
        obj is WgSecretKey other && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(_value), Encoding.ASCII.GetBytes(other._value));

    public override int GetHashCode() => 0;

    /// <summary>Génère 32 octets aléatoires (format PSK de WireGuard, équivalent à <c>wg genpsk</c>).</summary>
    public static WgSecretKey GeneratePresharedKey() => new(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
}

/// <summary>Paire de clés WireGuard. La génération est déléguée (wg.exe sous Windows).</summary>
public sealed record WgKeyPair(WgSecretKey PrivateKey, WgPublicKey PublicKey);

public interface IWgKeyGenerator
{
    WgKeyPair GenerateKeyPair();
    WgSecretKey GeneratePresharedKey();
}

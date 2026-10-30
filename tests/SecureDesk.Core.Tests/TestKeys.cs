using System.Security.Cryptography;
using SecureDesk.Core.Security;

namespace SecureDesk.Core.Tests;

/// <summary>Générateur de clés de test : 32 octets aléatoires (pas de vraie dérivation Curve25519, inutile ici).</summary>
internal sealed class FakeKeyGenerator : IWgKeyGenerator
{
    public WgKeyPair GenerateKeyPair() =>
        new(new WgSecretKey(RandomKey()), new WgPublicKey(RandomKey()));

    public WgSecretKey GeneratePresharedKey() => WgSecretKey.GeneratePresharedKey();

    public static string RandomKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
}

internal sealed class FixedClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

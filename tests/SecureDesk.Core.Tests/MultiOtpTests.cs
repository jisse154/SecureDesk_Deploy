using SecureDesk.Core.Config;
using SecureDesk.Core.MultiOtp;

namespace SecureDesk.Core.Tests;

public class MultiOtpTests
{
    [Fact]
    public void Distant_seulement_impose_1e_et_laisse_credui_desactive()
    {
        var v = MultiOtpPlan.ActivationValues(TwoFactorScope.RemoteOnly);
        Assert.Equal("1e", v["cpus_logon"]);
        Assert.Equal("1e", v["cpus_unlock"]);
        Assert.Equal("3d", v["cpus_credui"]);
    }

    [Fact]
    public void Distant_et_local_impose_0e()
    {
        var v = MultiOtpPlan.ActivationValues(TwoFactorScope.RemoteAndLocal);
        Assert.Equal("0e", v["cpus_logon"]);
        Assert.Equal("0e", v["cpus_unlock"]);
    }

    [Fact]
    public void Jamais_de_mode_d_en_activation()
    {
        // « d » laisserait les autres fournisseurs (mot de passe seul) disponibles en RDP : contournement du TOTP.
        foreach (var scope in Enum.GetValues<TwoFactorScope>())
        {
            var v = MultiOtpPlan.ActivationValues(scope);
            Assert.EndsWith("e", v["cpus_logon"], StringComparison.Ordinal);
            Assert.EndsWith("e", v["cpus_unlock"], StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Desactivation_3d_partout()
    {
        Assert.All(MultiOtpPlan.DisabledValues().Values, v => Assert.Equal("3d", v));
        Assert.Equal(3, MultiOtpPlan.DisabledValues().Count);
        Assert.False(MultiOtpPlan.IsActive("3d"));
        Assert.True(MultiOtpPlan.IsActive("1e"));
        Assert.True(MultiOtpPlan.IsActive("0e"));
        Assert.False(MultiOtpPlan.IsActive(null));
    }

    [Fact]
    public void Installation_msi_desactivee_et_locale()
    {
        var props = MultiOtpPlan.MsiProperties();
        Assert.Contains("CPUS_LOGON=3d", props);
        Assert.Contains("CPUS_UNLOCK=3d", props);
        Assert.Contains("CPUS_CREDUI=3d", props);
        Assert.Contains("MULTIOTP_URL=\"\"", props);
        Assert.Contains("MULTIOTP_TWO_STEP_HIDE_OTP=1", props);
        Assert.Contains("MULTIOTP_WITHOUT2FA=0", props);
    }

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Totp_vecteurs_rfc6238_sha1(long unix, string expected)
    {
        var secret = "12345678901234567890"u8.ToArray();
        Assert.Equal(expected, Totp.Compute(secret, DateTimeOffset.FromUnixTimeSeconds(unix), 8));
    }

    [Fact]
    public void Base32_aller_retour()
    {
        var data = "12345678901234567890"u8.ToArray();
        var b32 = Totp.Base32Encode(data);
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", b32);
        Assert.Equal(data, Totp.Base32Decode(b32));
    }

    [Fact]
    public void Uri_otpauth_analysee_sans_exposer_la_graine()
    {
        const string output = "Some text\r\notpauth://totp/multiOTP%3Aalice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30&issuer=multiOTP\r\n";
        Assert.True(OtpAuthUri.TryParse(output, out var uri));
        Assert.Equal("totp", uri!.Type);
        Assert.Equal(6, uri.Digits);
        Assert.DoesNotContain("GEZDG", uri.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("otpauth://totp/", uri.ToProvisioningText(output), StringComparison.Ordinal);
        Assert.Equal(Totp.Compute("12345678901234567890"u8.ToArray(), DateTimeOffset.FromUnixTimeSeconds(59), 6), uri.CurrentCode(DateTimeOffset.FromUnixTimeSeconds(59)));
    }

    [Fact]
    public void Uri_otpauth_invalide()
    {
        Assert.False(OtpAuthUri.TryParse("rien", out _));
        Assert.False(OtpAuthUri.TryParse("otpauth://totp/x?issuer=a", out _));
    }

    [Fact]
    public void Codes_de_retour_decrits()
    {
        Assert.Contains("déjà", MultiOtpExitCodes.Describe(26), StringComparison.Ordinal);
        Assert.Contains("inconnu", MultiOtpExitCodes.Describe(21), StringComparison.Ordinal);
    }
}

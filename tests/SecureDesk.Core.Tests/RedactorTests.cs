using SecureDesk.Core.Logging;

namespace SecureDesk.Core.Tests;

public class RedactorTests
{
    [Fact]
    public void Masque_cles_wireguard()
    {
        var key = FakeKeyGenerator.RandomKey();
        var r = Redactor.Redact($"clé {key} fin");
        Assert.DoesNotContain(key, r, StringComparison.Ordinal);
        Assert.Contains(Redactor.Mask, r, StringComparison.Ordinal);
    }

    [Fact]
    public void Masque_lignes_de_config()
    {
        var r = Redactor.Redact("[Interface]\nPrivateKey = abc\nPresharedKey=def\nAddress = 10.77.0.1/24");
        Assert.DoesNotContain("abc", r, StringComparison.Ordinal);
        Assert.DoesNotContain("def", r, StringComparison.Ordinal);
        Assert.Contains("Address = 10.77.0.1/24", r, StringComparison.Ordinal);
    }

    [Fact]
    public void Masque_otpauth_et_graines()
    {
        var uri = "otpauth://totp/multiOTP:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=multiOTP";
        var r = Redactor.Redact("lien " + uri);
        Assert.DoesNotContain("JBSWY3DPEHPK3PXP", r, StringComparison.Ordinal);
        Assert.DoesNotContain("otpauth", r, StringComparison.Ordinal);

        Assert.DoesNotContain("JBSWY3DPEHPK3PXP", Redactor.Redact("seed JBSWY3DPEHPK3PXP"), StringComparison.Ordinal);
        Assert.DoesNotContain("3132333435363738393031323334353637383930", Redactor.Redact("3132333435363738393031323334353637383930"), StringComparison.Ordinal);
        Assert.Contains("password=" + Redactor.Mask, Redactor.Redact("password=Secret123!"), StringComparison.Ordinal);
    }

    [Fact]
    public void Laisse_le_texte_ordinaire_et_les_empreintes_sha256()
    {
        const string s = "Tunnel securedesk actif, pair pc-perso (AB12-CD34-EF56-7890), 10.77.0.2, port 41234";
        Assert.Equal(s, Redactor.Redact(s));
        var hash = "sha256:" + new string('A', 64);
        Assert.Equal(hash, Redactor.Redact(hash));
    }

    [Fact]
    public void Memorylog_redige()
    {
        var log = new MemoryLog();
        var key = FakeKeyGenerator.RandomKey();
        log.Info("PrivateKey = " + key);
        Assert.DoesNotContain(key, log.AllText(), StringComparison.Ordinal);
    }

    [Fact]
    public void Filelog_redige_sur_disque()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sd-log-" + Guid.NewGuid().ToString("N"));
        try
        {
            var key = FakeKeyGenerator.RandomKey();
            string path;
            using (var log = new FileLog(dir))
            {
                log.Info("clé " + key);
                path = log.Path;
            }

            Assert.DoesNotContain(key, File.ReadAllText(path), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}

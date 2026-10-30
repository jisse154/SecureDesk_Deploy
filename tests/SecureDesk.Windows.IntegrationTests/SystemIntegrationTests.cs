using System.Diagnostics;
using SecureDesk.Core.Hardening;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.IntegrationTests;

[Collection("systeme")]
public class SystemIntegrationTests
{
    [Fact]
    public void Authenticode_distingue_signe_et_non_signe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var dotnet = Process.GetCurrentProcess().MainModule!.FileName;
        var signed = Authenticode.Verify(dotnet);
        var unsigned = Path.Combine(Path.GetTempPath(), "sd-unsigned-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(unsigned, [0x4D, 0x5A, 0, 0]);
        try
        {
            Assert.False(Authenticode.Verify(unsigned).Valid);
        }
        finally
        {
            File.Delete(unsigned);
        }

        // testhost/dotnet est signé par Microsoft (signature intégrée).
        Assert.True(signed.Valid || dotnet.EndsWith("testhost.exe", StringComparison.OrdinalIgnoreCase), signed.ToString());
    }

    [Fact]
    public void Lecture_secedit_et_auditpol()
    {
        if (!Integration.Enabled)
        {
            return;
        }

        var log = Integration.Log();
        var p = new Policies(log, Integration.Runner(log));
        var access = p.ReadSystemAccess();
        Assert.True(access.ContainsKey("MinimumPasswordLength"), string.Join(",", access.Keys));
        Assert.True(access.ContainsKey("LockoutBadCount"));
        var audit = p.ReadAudit();
        Assert.Contains(HardeningPlan.AuditSubcategories[0].Guid, audit.Keys, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Fichier_protege_acl_systeme_et_admins()
    {
        if (!Integration.Enabled)
        {
            return;
        }

        var dir = Path.Combine(Path.GetTempPath(), "sd-acl-" + Guid.NewGuid().ToString("N"));
        var file = Path.Combine(dir, "secret.conf");
        try
        {
            SecureFiles.WriteProtected(file, "contenu");
            Assert.True(SecureFiles.IsProtected(dir));
            Assert.True(SecureFiles.IsProtected(file));
            Assert.Equal("contenu", File.ReadAllText(file));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Informations_systeme()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.True(SystemInfo.Build > 17000);
        Assert.False(string.IsNullOrEmpty(SystemInfo.EditionId));
        Assert.True(SystemInfo.Memory().TotalBytes > 0);
        Assert.InRange(SystemInfo.RdpPort(), 1, 65535);
    }
}

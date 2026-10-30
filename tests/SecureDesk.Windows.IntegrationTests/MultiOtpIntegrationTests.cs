using SecureDesk.Core.Installers;
using SecureDesk.Core.MultiOtp;
using SecureDesk.Windows.MultiOtp;

namespace SecureDesk.Windows.IntegrationTests;

/// <summary>
/// multiOTP sur runner éphémère : installation en mode DÉSACTIVÉ (cpus_* = 3d) — le Credential Provider n'est jamais
/// activé ici (aucune ouverture de session interactive n'a lieu sur un runner). Parcours CLI complet de l'enrôlement.
/// </summary>
[Collection("systeme")]
public class MultiOtpIntegrationTests
{
    [Fact]
    public void Installation_desactivee_enrolement_verification_codes_de_secours()
    {
        if (!Integration.Enabled || Environment.GetEnvironmentVariable("SECUREDESK_IT_MULTIOTP") != "1")
        {
            return;
        }

        var manifest = InstallerManifest.Embedded();
        Assert.False(string.IsNullOrEmpty(manifest.MultiOtp.Sha256), "multiOTP non épinglé (scripts/pin-installers.ps1)");
        var log = Integration.Log();
        var ops = new MultiOtpOps(log, Integration.Runner(log));
        ops.Install(manifest, null, null, null);

        var st = MultiOtpOps.Status();
        Assert.True(st.Installed);
        Assert.False(st.Active);
        Assert.Equal("3d", st.CpusLogon);
        Assert.Equal("3d", st.CpusUnlock);

        const string user = "sditest";
        try
        {
            ops.CreateUser(user);
            var (uri, qr) = ops.ProvisioningUri(user);
            Assert.StartsWith("otpauth://", qr, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(MultiOtpExitCodes.TokenAccepted, ops.CheckCode(user, uri.CurrentCode(DateTimeOffset.UtcNow)));
            // Un code déjà utilisé est refusé (protection contre le rejeu).
            Assert.NotEqual(MultiOtpExitCodes.TokenAccepted, ops.CheckCode(user, uri.CurrentCode(DateTimeOffset.UtcNow)));
            var scratch = ops.ScratchList(user);
            Assert.NotEmpty(scratch);
            Assert.Empty(MultiOtpOps.LeftoverProvisioningFiles());
            Assert.DoesNotContain(qr, log.AllText(), StringComparison.Ordinal);
        }
        finally
        {
            ops.DeleteUser(user);
        }

        // Toujours inactif à la fin.
        Assert.False(MultiOtpOps.Status().Active);
    }
}

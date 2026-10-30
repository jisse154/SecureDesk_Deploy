using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.IntegrationTests;

public class MsiCommandLineTests
{
    [Fact]
    public void Syntaxe_windows_sans_echappement_c()
    {
        var cl = InstallerSource.MsiCommandLine("/i", @"C:\a b\x.msi", ["MULTIOTP_URL=\"\"", "CPUS_LOGON=3d", "DO_NOT_LAUNCH=1"], @"C:\logs\x.log");
        Assert.Equal("/i \"C:\\a b\\x.msi\" /qn /norestart MULTIOTP_URL=\"\" CPUS_LOGON=3d DO_NOT_LAUNCH=1 /l*v \"C:\\logs\\x.log\"", cl);
        Assert.DoesNotContain("\\\"", cl, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("A=1 /x")]
    [InlineData("A=\"b\"")]
    [InlineData("a=1")]
    [InlineData("A=1&calc")]
    public void Proprietes_dangereuses_refusees(string prop)
    {
        Assert.Throws<ArgumentException>(() => InstallerSource.MsiCommandLine("/i", "x.msi", [prop], "l.log"));
    }
}

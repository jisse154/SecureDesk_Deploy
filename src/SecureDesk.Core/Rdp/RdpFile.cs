using System.Globalization;
using System.Text;
using SecureDesk.Core.Config;

namespace SecureDesk.Core.Rdp;

/// <summary>Fichier .rdp pour mstsc. Aucun mot de passe n'est jamais enregistré.</summary>
public static class RdpFile
{
    public static string Build(string serverTunnelIp, int rdpPort, RedirectionOptions redirections, string? userName = null)
    {
        ArgumentNullException.ThrowIfNull(serverTunnelIp);
        ArgumentNullException.ThrowIfNull(redirections);
        var address = rdpPort == 3389 ? serverTunnelIp : string.Create(CultureInfo.InvariantCulture, $"{serverTunnelIp}:{rdpPort}");
        var lines = new List<string>
        {
            "full address:s:" + address,
            "prompt for credentials:i:1",
            // NLA (CredSSP) : le mot de passe est saisi dans mstsc avant l'ouverture de la session.
            "enablecredsspsupport:i:1",
            // 2 = avertir si l'identité du serveur ne peut être vérifiée (certificat auto-signé du PC serveur).
            "authentication level:i:2",
            "negotiate security layer:i:1",
            "redirectclipboard:i:" + Flag(redirections.Clipboard),
            "redirectprinters:i:" + Flag(redirections.Printers),
            "drivestoredirect:s:" + (redirections.Drives ? "*" : string.Empty),
            "redirectdrives:i:" + Flag(redirections.Drives),
            "redirectcomports:i:0",
            "redirectsmartcards:i:0",
            "redirectposdevices:i:0",
            "devicestoredirect:s:",
            "audiocapturemode:i:0",
            "camerastoredirect:s:",
            "usbdevicestoredirect:s:",
            "autoreconnection enabled:i:1",
            "screen mode id:i:2",
            "use multimon:i:0",
            "session bpp:i:32",
        };
        if (!string.IsNullOrWhiteSpace(userName))
        {
            lines.Add("username:s:" + userName.Trim());
        }

        return string.Join("\r\n", lines) + "\r\n";
    }

    private static string Flag(bool value) => value ? "1" : "0";

    /// <summary>Encodage attendu par mstsc : UTF-16 LE avec BOM.</summary>
    public static Encoding FileEncoding => new UnicodeEncoding(bigEndian: false, byteOrderMark: true);
}

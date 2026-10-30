using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SecureDesk.Core.Net;

namespace SecureDesk.Windows.Sys;

public sealed record LanInfo(string InterfaceName, string Address, Ipv4Cidr Subnet, string? Gateway);

public static partial class SystemInfo
{
    private const string CurrentVersion = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    public static string? EditionId => RegistryOps.ReadString(CurrentVersion, "EditionID");
    public static string? ProductName => RegistryOps.ReadString(CurrentVersion, "ProductName");
    public static string? DisplayVersion => RegistryOps.ReadString(CurrentVersion, "DisplayVersion");

    public static int Build =>
        int.TryParse(RegistryOps.ReadString(CurrentVersion, "CurrentBuildNumber"), out var b) ? b : 0;

    /// <summary>Windows 11 = build 22000 et plus (ProductName indique encore « Windows 10 » sur Windows 11).</summary>
    public static bool IsWindows11 => Build >= 22000;

    /// <summary>Éditions Pro et supérieures : seules celles-ci ont le rôle serveur RDP.</summary>
    public static bool IsProOrBetter => EditionId is "Professional" or "ProfessionalWorkstation" or "ProfessionalEducation" or "Enterprise" or "Education";

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Redémarrage en attente (CBS, Windows Update, renommages de fichiers).</summary>
    public static IReadOnlyList<string> PendingRebootReasons()
    {
        var reasons = new List<string>();
        using var hklm = RegistryOps.Hklm();
        if (hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") is { } k1)
        {
            k1.Dispose();
            reasons.Add("maintenance de composants Windows (CBS)");
        }

        if (hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") is { } k2)
        {
            k2.Dispose();
            reasons.Add("Windows Update");
        }

        if (RegistryOps.Read(@"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") is string[] { Length: > 0 })
        {
            reasons.Add("renommages de fichiers en attente");
        }

        return reasons;
    }

    public static int LogicalProcessors => Environment.ProcessorCount;

    public static (ulong TotalBytes, ulong AvailableBytes) Memory()
    {
        var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        return GlobalMemoryStatusEx(ref status) ? (status.TotalPhys, status.AvailPhys) : (0, 0);
    }

    public static double CpuLoadPercent()
    {
        using var counter = new PerformanceCounterLite();
        return counter.SampleCpu();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

    // ---------- Session ----------

    private const int SmRemoteSession = 0x1000;

    [LibraryImport("user32.dll")]
    private static partial int GetSystemMetrics(int index);

    [LibraryImport("kernel32.dll")]
    private static partial uint WTSGetActiveConsoleSessionId();

    /// <summary>
    /// Le processus tourne-t-il dans une session Bureau à distance ? Double contrôle : métrique système
    /// SM_REMOTESESSION et comparaison avec la session console active.
    /// </summary>
    public static bool IsRemoteSession()
    {
        if (GetSystemMetrics(SmRemoteSession) != 0)
        {
            return true;
        }

        var console = WTSGetActiveConsoleSessionId();
        var current = (uint)Process.GetCurrentProcess().SessionId;
        return console != 0xFFFFFFFF && console != current;
    }

    // ---------- Réseau ----------

    /// <summary>Interface LAN principale : active, IPv4, avec passerelle par défaut, hors tunnel/virtuelle.</summary>
    public static LanInfo? DetectLan()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up
                                 && n.NetworkInterfaceType is not NetworkInterfaceType.Loopback and not NetworkInterfaceType.Tunnel
                                 && !n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase)))
        {
            var props = nic.GetIPProperties();
            var gw = props.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any));
            if (gw is null)
            {
                continue;
            }

            var ua = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
            if (ua is null)
            {
                continue;
            }

            var cidr = Ipv4Cidr.FromAddressAndMask(ua.Address, ua.IPv4Mask);
            return new LanInfo(nic.Name, ua.Address.ToString(), new Ipv4Cidr(cidr.Network, cidr.PrefixLength), gw.Address.ToString());
        }

        return null;
    }

    public static bool IsUdpPortInUse(int port) =>
        IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(e => e.Port == port);

    public static IReadOnlyList<System.Net.IPEndPoint> TcpListeners(int port) =>
        [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(e => e.Port == port)];

    public static string MachineName => Environment.MachineName;

    /// <summary>Port RDP effectif (TSplus permet de le changer dans l'AdminTool).</summary>
    public static int RdpPort() =>
        RegistryOps.ReadDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber") ?? 3389;

    public static bool RdpEnabled() =>
        RegistryOps.ReadDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0;

    private sealed class PerformanceCounterLite : IDisposable
    {
        public double SampleCpu()
        {
            // Mesure simple sur 500 ms à partir des temps système (sans compteur de performance localisé).
            if (!GetSystemTimes(out var idle1, out var kernel1, out var user1))
            {
                return -1;
            }

            Thread.Sleep(500);
            if (!GetSystemTimes(out var idle2, out var kernel2, out var user2))
            {
                return -1;
            }

            var idle = idle2 - idle1;
            var total = (kernel2 - kernel1) + (user2 - user1);
            return total == 0 ? 0 : 100.0 * (total - idle) / total;
        }

        public void Dispose()
        {
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSystemTimes(out long idleTime, out long kernelTime, out long userTime);
}

using SecureDesk.Core.Logging;
using SecureDesk.Windows.Sys;

namespace SecureDesk.Windows.IntegrationTests;

/// <summary>
/// Tests qui MODIFIENT le système (pare-feu, installations) : exécutés uniquement sur un runner éphémère,
/// quand SECUREDESK_INTEGRATION=1 et que le processus est administrateur. Sinon ils sont neutres.
/// </summary>
internal static class Integration
{
    public static bool Enabled =>
        OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("SECUREDESK_INTEGRATION") == "1"
        && SystemInfo.IsAdministrator();

    public static MemoryLog Log() => new();

    public static ProcessRunner Runner(ILog log) => new(log);
}

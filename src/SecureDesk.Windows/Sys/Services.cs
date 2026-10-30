using System.ServiceProcess;

namespace SecureDesk.Windows.Sys;

public static class Services
{
    public static ServiceController? Find(string name) =>
        ServiceController.GetServices().FirstOrDefault(s => string.Equals(s.ServiceName, name, StringComparison.OrdinalIgnoreCase));

    public static bool Exists(string name)
    {
        using var s = Find(name);
        return s is not null;
    }

    public static ServiceControllerStatus? Status(string name)
    {
        using var s = Find(name);
        return s?.Status;
    }

    public static ServiceStartMode? StartMode(string name)
    {
        using var s = Find(name);
        return s?.StartType;
    }

    public static void SetStartMode(ProcessRunner runner, string name, bool automatic)
    {
        ArgumentNullException.ThrowIfNull(runner);
        runner.RunChecked(ProcessRunner.SystemExe("sc.exe"), ["config", name, "start=", automatic ? "auto" : "demand"]);
    }

    public static void Start(string name, TimeSpan? timeout = null)
    {
        using var s = Find(name) ?? throw new InvalidOperationException($"Service introuvable : {name}");
        if (s.Status != ServiceControllerStatus.Running)
        {
            s.Start();
            s.WaitForStatus(ServiceControllerStatus.Running, timeout ?? TimeSpan.FromSeconds(60));
        }
    }

    public static void Stop(string name, TimeSpan? timeout = null)
    {
        using var s = Find(name);
        if (s is not null && s.Status != ServiceControllerStatus.Stopped)
        {
            s.Stop();
            s.WaitForStatus(ServiceControllerStatus.Stopped, timeout ?? TimeSpan.FromSeconds(60));
        }
    }

    public static void Restart(string name)
    {
        Stop(name);
        Start(name);
    }

    public static IReadOnlyList<(string Name, string DisplayName, ServiceControllerStatus Status)> FindByDisplayName(string contains) =>
        [.. ServiceController.GetServices()
            .Where(s => s.DisplayName.Contains(contains, StringComparison.OrdinalIgnoreCase) || s.ServiceName.Contains(contains, StringComparison.OrdinalIgnoreCase))
            .Select(s => (s.ServiceName, s.DisplayName, s.Status))];
}

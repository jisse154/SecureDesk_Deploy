using SecureDesk.Core.Config;

namespace SecureDesk.Core.Cli;

public static class ConfigOverrides
{
    /// <summary>Les options de la ligne de commande priment sur le fichier JSON.</summary>
    public static SecureDeskConfig Apply(SecureDeskConfig config, CommandLine cl)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(cl);
        var s = config.Server;
        if (cl.Get("endpoint") is { } endpoint)
        {
            s.EndpointHost = endpoint;
        }

        if (cl.GetInt("port") is { } port)
        {
            s.ListenPort = port;
        }

        if (cl.Get("subnet") is { } subnet)
        {
            s.TunnelSubnet = subnet;
        }

        if (cl.Get("users") is { } users)
        {
            s.Users = [.. users.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(u => new UserSpec { Name = u })];
        }

        if (cl.Has("allow-lan"))
        {
            s.AllowLan = true;
        }

        if (cl.Get("lan-subnet") is { } lan)
        {
            s.AllowLan = true;
            s.LanSubnet = lan;
        }

        if (cl.Get("scope") is { } scope)
        {
            s.TwoFactor.Scope = scope.ToLowerInvariant() switch
            {
                "remote" => TwoFactorScope.RemoteOnly,
                "all" => TwoFactorScope.RemoteAndLocal,
                _ => throw new CommandLineException("--scope : « remote » (distant seulement) ou « all » (distant et local)."),
            };
        }

        if (cl.Has("auto-start") && cl.Has("manual-start"))
        {
            throw new CommandLineException("--auto-start et --manual-start sont incompatibles.");
        }

        if (cl.Has("auto-start"))
        {
            config.Client.AutoStartTunnel = true;
        }

        if (cl.Has("manual-start"))
        {
            config.Client.AutoStartTunnel = false;
        }

        var inst = config.Installers;
        inst.WireGuardMsi = cl.Get("wireguard-msi") ?? inst.WireGuardMsi;
        inst.MultiOtpMsi = cl.Get("multiotp-msi") ?? inst.MultiOtpMsi;
        inst.VcRedist = cl.Get("vcredist") ?? inst.VcRedist;
        inst.TsplusSetup = cl.Get("tsplus-setup") ?? inst.TsplusSetup;
        if (cl.Has("tsplus-silent"))
        {
            inst.TsplusSilent = true;
        }

        return config;
    }
}

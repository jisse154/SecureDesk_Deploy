using System.Globalization;
using System.Reflection;
using SecureDesk.Core.Cli;
using SecureDesk.Core.Config;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.State;
using SecureDesk.Windows.Ops;
using SecureDesk.Windows.Sys;

namespace SecureDesk.App.Cli;

internal static class Commands
{
    public static string Version =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public static int Run(CommandLine cl)
    {
        if (cl.Verb is "help")
        {
            Console.WriteLine(CommandLine.Usage());
            return 0;
        }

        if (cl.Verb is "version")
        {
            Console.WriteLine("SecureDesk " + Version);
            return 0;
        }

        if (!SystemInfo.IsAdministrator())
        {
            Console.Error.WriteLine("SecureDesk doit être lancé en tant qu'administrateur.");
            return 2;
        }

        var config = cl.Get("config") is { } path ? SecureDeskConfig.Load(path) : new SecureDeskConfig();
        ConfigOverrides.Apply(config, cl);
        SecureFiles.EnsureProtectedDirectory(SecureFiles.ProgramDataRoot);
        using var file = new FileLog(SecureFiles.LogsDir);
        var ui = new ConsoleUi(cl.Has("yes"));
        ILog log = cl.Has("verbose") ? new CompositeLog(file, new ConsoleLog()) : file;
        log.Info($"SecureDesk {Version} — commande « {cl.Verb} »{(cl.DryRun ? " (dry-run)" : string.Empty)}");
        var ctx = new Context(log, ui, config, new FileStateStore(SecureFiles.StatePath), cl.DryRun)
        {
            Sha256Override = cl.Get("sha256"),
            ConsoleAccessAcknowledged = cl.Has("i-have-console-access"),
            AssumeYes = cl.Has("yes"),
        };
        if (cl.DryRun)
        {
            ui.Show("Mode --dry-run", ["Aucune modification ne sera faite : les actions sont seulement listées (« à faire » / « déjà conforme »)."]);
        }

        try
        {
            Dispatch(cl, ctx, ui);
            return 0;
        }
        catch (Exception ex) when (ex is OperationException or PairingException or CommandLineException or InstallerVerificationException or FileNotFoundException or ProcessFailedException or InvalidOperationException or UnauthorizedAccessException)
        {
            log.Error(ex.Message);
            log.Debug(ex.ToString());
            ui.Error(ex.Message);
            Console.Error.WriteLine($"Journal : {file.Path}");
            return 1;
        }
    }

    private static void Dispatch(CommandLine cl, Context ctx, ConsoleUi ui)
    {
        var server = new ServerOps(ctx);
        var client = new ClientOps(ctx);
        var twoFa = new TwoFactorOps(ctx);
        string Arg(string what) => cl.Argument ?? throw new CommandLineException($"Argument manquant : {what}.");

        switch (cl.Verb)
        {
            case "wizard":
                throw new CommandLineException("L'assistant graphique se lance sans argument (double-clic sur SecureDesk.exe).");
            case "precheck":
                var checks = ctx.State.Role == "client" ? Checks.Client() : Checks.Server(ctx);
                foreach (var c in checks)
                {
                    PrintCheck(ui, c);
                }

                break;
            case "init":
                server.Init(cl.Get("out"), cl.Get("name") ?? "pc-perso");
                break;
            case "invite":
                server.Invite(cl.Get("name") ?? cl.Argument ?? throw new CommandLineException("--name <nom du pair> requis."), cl.Get("out"));
                break;
            case "add-peer":
                server.AddPeer(Arg("chemin du fichier pairing-client.sdpair"));
                break;
            case "list-peers":
                ui.Show("Pairs", server.ListPeers());
                break;
            case "revoke-peer":
                server.RevokePeer(Arg("nom du pair"));
                break;
            case "rotate-keys":
                if (cl.Has("server"))
                {
                    server.RotateServerKeys(cl.Get("out"));
                }
                else if (cl.Get("peer") is { } peer)
                {
                    server.RotatePeer(peer, cl.Get("out"));
                }
                else
                {
                    throw new CommandLineException("rotate-keys : précisez --server ou --peer <nom>. Côté client, la rotation se fait par un nouvel appairage (join).");
                }

                break;
            case "tsplus-check":
                server.Tsplus(waitForManualInstall: !cl.Has("yes"));
                break;
            case "accounts":
                server.Accounts(name => ui.AskSecret($"Mot de passe du nouveau compte « {name} »", confirm: true));
                break;
            case "harden":
                server.Harden();
                break;
            case "install-2fa":
                twoFa.Install();
                break;
            case "enroll-user":
                twoFa.Enroll(Arg("nom du compte Windows"));
                break;
            case "enable-2fa":
                twoFa.Enable(ctx.Config.Server.TwoFactor.Scope);
                break;
            case "confirm-2fa":
                twoFa.Confirm();
                break;
            case "disable-2fa":
                twoFa.Disable(cl.Has("from-probation"));
                break;
            case "join":
                client.Join(Arg("chemin du fichier pairing-server.sdpair"), cl.Get("out"));
                break;
            case "rdp-shortcut":
                client.RdpShortcut();
                break;
            case "test":
                foreach (var c in client.Test())
                {
                    PrintCheck(ui, c);
                }

                break;
            case "diagnose":
                var lines = ctx.State.Role == "client" ? client.Report() : server.Report();
                foreach (var l in lines)
                {
                    Console.WriteLine(l);
                }

                if (cl.Get("export") is { } export)
                {
                    ui.Info("Rapport exporté (sans secret) : " + Diagnostics.Export(lines, export));
                }

                break;
            case "report":
                var report = server.Report();
                ui.Show("Rapport final", report);
                var reportPath = cl.Get("export") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    string.Create(CultureInfo.InvariantCulture, $"SecureDesk-rapport-{DateTime.Now:yyyyMMdd-HHmm}.txt"));
                ui.Info("Rapport exporté : " + Diagnostics.Export(report, reportPath));
                break;
            case "uninstall":
                new Uninstaller(ctx).Run(cl.Has("remove-accounts"));
                break;
            default:
                throw new CommandLineException($"Commande non gérée : {cl.Verb}");
        }
    }

    private static void PrintCheck(ConsoleUi ui, CheckItem c)
    {
        switch (c.Level)
        {
            case CheckLevel.Ok: ui.Info(c.ToString()); break;
            case CheckLevel.Warning: ui.Warn(c.ToString()); break;
            default: ui.Error(c.ToString()); break;
        }
    }

    private sealed class ConsoleLog : ILog
    {
        public void Write(LogLevel level, string message) => Console.WriteLine($"  · {Redactor.Redact(message)}");
    }
}

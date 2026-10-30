using SecureDesk.Core.Logging;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.Rdp;
using SecureDesk.Core.State;
using SecureDesk.Core.WireGuard;
using SecureDesk.Windows.Sys;
using SecureDesk.Windows.WireGuard;

namespace SecureDesk.Windows.Ops;

/// <summary>Rôle client : join, raccourci RDP, test.</summary>
public sealed class ClientOps(Context ctx)
{
    private readonly WireGuardOps _wg = new(ctx.Log, ctx.Runner);

    /// <summary>
    /// Importe le fichier serveur, génère les clés du client LOCALEMENT, installe le tunnel et exporte le fichier client.
    /// Relancer join avec une nouvelle invitation remplace proprement l'ancienne configuration (réappairage).
    /// </summary>
    public string Join(string serverFile, string? clientOutput)
    {
        if (ctx.State.Role == "server")
        {
            throw new OperationException("Ce PC est configuré comme SERVEUR SecureDesk : join n'est pas possible ici.");
        }

        foreach (var c in Checks.Client())
        {
            if (c.Level == CheckLevel.Blocking)
            {
                throw new OperationException(c.ToString());
            }

            ctx.Ui.Info(c.ToString());
        }

        var json = File.ReadAllText(serverFile);
        ServerInvitation invitation;
        while (true)
        {
            var pass = ctx.Ui.AskSecret("Phrase de passe du fichier d'appairage", confirm: false);
            try
            {
                invitation = PairingFile.ReadServer(json, pass, ctx.Clock);
                break;
            }
            catch (PairingException ex) when (ex.Message.Contains("Phrase de passe", StringComparison.Ordinal))
            {
                ctx.Ui.Warn(ex.Message);
                if (!ctx.Ui.Confirm("Réessayer ?", true))
                {
                    throw;
                }
            }
        }

        ctx.Ui.Info($"Invitation pour « {invitation.PeerName} » : serveur {invitation.EndpointHost}:{invitation.EndpointPort}, IP tunnel {invitation.ClientTunnelIp}.");
        ctx.Ui.Info($"Empreinte de la clé du serveur : {invitation.ServerPublicKey.Fingerprint} (elle doit correspondre à celle affichée sur le serveur).");
        if (!ctx.Ui.Confirm("L'empreinte correspond-elle ?", true))
        {
            throw new OperationException("Appairage annulé : empreinte du serveur non confirmée.");
        }

        var tunnel = ctx.Config.Server.TunnelName;
        var auto = ctx.Config.Client.AutoStartTunnel;
        if (ctx.DryRun)
        {
            ctx.Ui.Info($"[à faire] Installer WireGuard, générer les clés du client, créer le tunnel {tunnel} ({(auto ? "démarrage automatique" : "manuel via l'icône WireGuard")}), exporter le fichier client, créer le raccourci RDP.");
            return string.Empty;
        }

        new SelfInstall(ctx.Log, ctx.Runner).EnsureInstalled();
        SecureFiles.EnsureProtectedDirectory(SecureFiles.ProgramDataRoot);
        if (_wg.EnsureInstalled(ctx.Manifest, ctx.Config.Installers.WireGuardMsi, ctx.Sha256Override))
        {
            ctx.State.RecordOriginal("installed:wireguard", "installed", new Dictionary<string, string?> { ["product"] = "WireGuard" });
            ctx.Save();
        }

        // Réappairage : suppression de l'ancienne configuration éventuelle.
        RemoveTunnel(tunnel);

        var keys = _wg.GenerateKeyPair();
        var config = TunnelConfigs.Client(keys.PrivateKey, invitation);
        if (auto)
        {
            _wg.WriteConf(tunnel, config);
            _wg.InstallTunnelService(tunnel, automaticStart: true);
            Services.Start(WireGuardOps.TunnelServiceName(tunnel));
        }
        else
        {
            _wg.ImportIntoManager(tunnel, config);
        }

        ctx.State.Role = "client";
        ctx.State.Client = new ClientState
        {
            TunnelName = tunnel,
            ServerTunnelIp = invitation.ServerTunnelIp,
            RdpPort = invitation.RdpPort,
            ClientPublicKey = keys.PublicKey.Value,
            ServerPublicKey = invitation.ServerPublicKey.Value,
            InvitationId = invitation.InvitationId,
            PeerName = invitation.PeerName,
            AutoStart = auto,
        };
        ctx.Save();

        var response = new ClientResponse
        {
            InvitationId = invitation.InvitationId,
            PeerName = invitation.PeerName,
            ClientPublicKey = keys.PublicKey,
            ClientTunnelIp = invitation.ClientTunnelIp,
            CreatedUtc = ctx.Clock.GetUtcNow(),
        };
        var path = string.IsNullOrWhiteSpace(clientOutput)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), PairingFile.ClientFileName)
            : Directory.Exists(clientOutput) ? Path.Combine(clientOutput, PairingFile.ClientFileName) : Path.GetFullPath(clientOutput);
        File.WriteAllText(path, PairingFile.WriteClient(response, invitation.PresharedKey));

        if (ctx.Config.Client.CreateRdpShortcut)
        {
            RdpShortcut();
        }

        ctx.Ui.Show("Appairage côté client terminé",
        [
            $"Fichier à rapporter sur le serveur : {path}",
            $"Empreinte de la clé du client : {keys.PublicKey.Fingerprint}",
            "Ce fichier ne contient que la clé publique : il n'est pas secret, mais il est authentifié (toute modification sera refusée).",
            "Sur le serveur : SecureDesk.exe add-peer <fichier>.",
            "Supprimez ensuite pairing-server.sdpair de la clé USB et de ce PC.",
            auto ? "Le tunnel démarre automatiquement avec Windows." : "Activez le tunnel depuis l'icône WireGuard (barre des tâches) avant de vous connecter.",
        ]);
        if (!ctx.AssumeYes && ctx.Ui.Confirm($"Supprimer maintenant le fichier serveur « {serverFile} » ?", true))
        {
            SecureFiles.BestEffortWipe(serverFile);
        }

        return path;
    }

    public string RdpShortcut()
    {
        var c = ctx.State.Client ?? throw new OperationException("Client non appairé : lancez d'abord « join ».");
        var name = ctx.Config.Client.RdpShortcutName + ".rdp";
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), name);
        if (ctx.DryRun)
        {
            ctx.Ui.Info($"[à faire] Raccourci {path}");
            return path;
        }

        File.WriteAllText(path, RdpFile.Build(c.ServerTunnelIp, c.RdpPort, ctx.Config.Server.Redirections), RdpFile.FileEncoding);
        c.RdpShortcutPath = path;
        ctx.Save();
        ctx.Ui.Info($"Raccourci Bureau à distance créé : {path} (aucun mot de passe enregistré).");
        return path;
    }

    public IReadOnlyList<CheckItem> Test() => Diagnostics.Client(ctx);

    public void RemoveTunnel(string tunnel)
    {
        _wg.RemoveFromManager(tunnel);
        _wg.UninstallTunnelService(tunnel);
        if (WireGuardOps.ConfExists(tunnel))
        {
            SecureFiles.BestEffortWipe(WireGuardOps.ConfPath(tunnel));
        }
    }

    public IReadOnlyList<string> Report() =>
        [.. new[] { "=== Rapport SecureDesk (client) ===" }.Concat(Test().Select(c => c.ToString())).Select(Redactor.Redact)];
}

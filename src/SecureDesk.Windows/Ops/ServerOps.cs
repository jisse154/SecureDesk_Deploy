using System.Globalization;
using SecureDesk.Core.Engine;
using SecureDesk.Core.Firewall;
using SecureDesk.Core.Hardening;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Net;
using SecureDesk.Core.Pairing;
using SecureDesk.Core.Security;
using SecureDesk.Core.State;
using SecureDesk.Core.WireGuard;
using SecureDesk.Windows.Firewall;
using SecureDesk.Windows.Sys;
using SecureDesk.Windows.Tsplus;
using SecureDesk.Windows.WireGuard;

namespace SecureDesk.Windows.Ops;

/// <summary>Rôle serveur : tunnel, pairs, pare-feu, comptes, durcissement, TSplus.</summary>
public sealed class ServerOps(Context ctx)
{
    private readonly WireGuardOps _wg = new(ctx.Log, ctx.Runner);
    private readonly FirewallOps _fw = new(ctx.Log, ctx.Runner);

    private string Tunnel => ctx.State.Server?.TunnelName ?? ctx.Config.Server.TunnelName;

    private Ipv4Cidr Subnet => Ipv4Cidr.Parse(ctx.State.Server?.TunnelSubnet ?? ctx.Config.Server.TunnelSubnet);

    private ServerState S => ctx.State.Server ??= new ServerState();

    // =====================================================================================
    // init : WireGuard + tunnel + pare-feu + première invitation
    // =====================================================================================

    public void Init(string? invitationOutput, string firstPeerName = "pc-perso")
    {
        var errors = ctx.Config.ValidateServer();
        if (errors.Count > 0)
        {
            throw new OperationException("Configuration invalide :\n - " + string.Join("\n - ", errors));
        }

        if (ctx.State.Role == "client")
        {
            throw new OperationException("Ce PC est déjà configuré comme CLIENT SecureDesk. Lancez « uninstall » avant de le configurer en serveur.");
        }

        EnsureBlockingChecksPass(Checks.Server(ctx));
        var cfg = ctx.Config.Server;
        var port = S.ListenPort > 0 ? S.ListenPort : cfg.ListenPort ?? PortSuggester.Suggest(SystemInfo.IsUdpPortInUse);
        if (S.ListenPort > 0 && cfg.ListenPort is { } wanted && wanted != S.ListenPort)
        {
            ctx.Ui.Warn(string.Create(CultureInfo.InvariantCulture,
                $"Le port {S.ListenPort} est déjà en service : la configuration demande {wanted}. Modifier le port impose de reconfigurer la box et les clients ; utilisez « uninstall » puis « init » pour le changer."));
        }

        var steps = new List<IStep>
        {
            new Step("self", "Copie de SecureDesk dans Program Files",
                () => File.Exists(SelfInstall.Exe) ? StepCheck.Ok() : StepCheck.Change(),
                () => new SelfInstall(ctx.Log, ctx.Runner).EnsureInstalled()),
            new Step("dirs", "Dossier %ProgramData%\\SecureDesk protégé (SYSTEM + Administrateurs)",
                () => Directory.Exists(SecureFiles.WireGuardDir) && SecureFiles.IsProtected(SecureFiles.ProgramDataRoot) ? StepCheck.Ok() : StepCheck.Change(),
                () =>
                {
                    SecureFiles.EnsureProtectedDirectory(SecureFiles.ProgramDataRoot);
                    SecureFiles.EnsureProtectedDirectory(SecureFiles.WireGuardDir);
                    SecureFiles.EnsureProtectedDirectory(SecureFiles.LogsDir);
                }),
            new Step("wg-install", "Installation de WireGuard (MSI officiel, signature vérifiée)",
                () => WireGuardOps.IsInstalled ? StepCheck.Ok() : StepCheck.Change(),
                () =>
                {
                    if (_wg.EnsureInstalled(ctx.Manifest, ctx.Config.Installers.WireGuardMsi, ctx.Sha256Override))
                    {
                        ctx.State.RecordOriginal("installed:wireguard", "installed", new Dictionary<string, string?> { ["product"] = "WireGuard" });
                    }
                }),
            new Step("wg-conf", string.Create(CultureInfo.InvariantCulture, $"Configuration du tunnel {Tunnel} ({TunnelConfigs.ServerIp(Subnet)}/{Subnet.PrefixLength}, UDP {port})"),
                () => WireGuardOps.ConfExists(Tunnel) && SecureFiles.IsProtected(WireGuardOps.ConfPath(Tunnel)) ? StepCheck.Ok("clés existantes conservées") : StepCheck.Change("génération des clés du serveur sur ce PC"),
                () =>
                {
                    WgSecretKey priv;
                    List<ServerPeer> peers = [];
                    if (WireGuardOps.ConfExists(Tunnel))
                    {
                        // Fichier existant mais ACL incorrecte : on le réécrit à l'identique avec la bonne ACL.
                        var existing = WireGuardOps.ReadConf(Tunnel);
                        priv = existing.Interface.PrivateKey;
                        peers = [.. existing.Peers.Where(p => p.PresharedKey is not null)
                            .Select(p => new ServerPeer(p.Name, p.PublicKey, p.PresharedKey!, p.AllowedIps[0].Split('/')[0]))];
                    }
                    else
                    {
                        priv = _wg.GenerateKeyPair().PrivateKey;
                    }

                    _wg.WriteConf(Tunnel, TunnelConfigs.Server(priv, Subnet, port, peers));
                    var pub = _wg.DerivePublicKey(priv);
                    ctx.State.Role = "server";
                    S.TunnelName = Tunnel;
                    S.TunnelSubnet = Subnet.ToString();
                    S.ListenPort = port;
                    S.EndpointHost = cfg.EndpointHost.Trim();
                    S.RdpPort = SystemInfo.RdpPort();
                    S.ServerPublicKey = pub.Value;
                    ctx.Log.Info($"Clé publique du serveur : empreinte {pub.Fingerprint}");
                }),
            new Step("wg-service", "Service de tunnel WireGuard (démarrage automatique)",
                () => WireGuardOps.TunnelServiceExists(Tunnel) && Services.StartMode(WireGuardOps.TunnelServiceName(Tunnel)) == System.ServiceProcess.ServiceStartMode.Automatic
                      && WireGuardOps.TunnelStatus(Tunnel) == System.ServiceProcess.ServiceControllerStatus.Running ? StepCheck.Ok() : StepCheck.Change(),
                () =>
                {
                    _wg.InstallTunnelService(Tunnel, automaticStart: true);
                    Services.Start(WireGuardOps.TunnelServiceName(Tunnel));
                }),
        };
        steps.AddRange(FirewallSteps(port));
        if (!string.IsNullOrEmpty(S.EndpointHost) && S.EndpointHost != cfg.EndpointHost.Trim() && !ctx.DryRun)
        {
            S.EndpointHost = cfg.EndpointHost.Trim();
        }

        ctx.Run(steps);
        if (ctx.DryRun)
        {
            ctx.Ui.Info($"[à faire] Création de l'invitation chiffrée pour « {firstPeerName} » (si aucun pair n'est encore appairé).");
            return;
        }

        if (S.Peers.Count == 0 && !S.Invitations.Any(i => !i.Consumed && i.ExpiresUtc > ctx.Clock.GetUtcNow()))
        {
            Invite(firstPeerName, invitationOutput);
        }
        else
        {
            ctx.Ui.Info("Un pair est déjà appairé ou une invitation est en attente : aucune nouvelle invitation (utilisez « invite » si besoin).");
        }

        ctx.Ui.Show("Configuration de la box Internet", BoxChecklist());
    }

    public IEnumerable<IStep> FirewallSteps(int wireGuardPort)
    {
        var cfg = ctx.Config.Server;
        Ipv4Cidr? lan = null;
        if (cfg.AllowLan)
        {
            lan = cfg.LanSubnet is not null ? Ipv4Cidr.Parse(cfg.LanSubnet) : SystemInfo.DetectLan()?.Subnet
                ?? throw new OperationException("Accès LAN demandé mais sous-réseau LAN introuvable : précisez server.lanSubnet.");
        }

        var rules = FirewallPlan.Build(Subnet, lan, SystemInfo.RdpPort(), cfg.ExtraProtectedTcpPorts, wireGuardPort);
        IReadOnlyList<ExistingRule>? cache = null;
        IReadOnlyList<ExistingRule> Existing() => cache ??= _fw.OwnedRules();

        yield return new Step("fw-profiles", "Pare-feu Windows actif sur tous les profils",
            () => FirewallOps.ProfileStates().Values.All(v => v) ? StepCheck.Ok() : StepCheck.Change(),
            () => _fw.EnableAllProfiles(ctx.State));

        var wantedNames = rules.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        yield return new Step("fw-stale", "Suppression des règles SecureDesk obsolètes",
            () => Existing().All(e => wantedNames.Contains(e.Name)) ? StepCheck.Ok() : StepCheck.Change(),
            () =>
            {
                foreach (var name in Existing().Select(e => e.Name).Where(n => !wantedNames.Contains(n)).Distinct().ToList())
                {
                    _fw.Remove(name);
                }

                cache = null;
            });

        foreach (var rule in rules)
        {
            yield return new Step("fw:" + rule.Name, "Pare-feu : " + rule,
                () => FirewallOps.IsCompliant(rule, Existing()) ? StepCheck.Ok() : StepCheck.Change(),
                () =>
                {
                    _fw.Apply(rule);
                    cache = null;
                });
        }
    }

    // =====================================================================================
    // Invitations et pairs
    // =====================================================================================

    /// <summary>Crée une invitation (PSK propre au pair, IP suivante) et exporte le fichier serveur chiffré.</summary>
    public string Invite(string peerName, string? output, bool reuseIp = false, string? fixedIp = null)
    {
        RequireServer();
        if (string.IsNullOrWhiteSpace(peerName) || peerName.Length > 32 || peerName.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))
        {
            throw new OperationException("Nom de pair invalide (lettres, chiffres, - _ . ; 32 caractères maximum).");
        }

        if (!reuseIp && S.Peers.Any(p => p.Name.Equals(peerName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new OperationException($"Le pair « {peerName} » existe déjà. Pour le réappairer : revoke-peer {peerName}, puis invite --name {peerName}.");
        }

        var now = ctx.Clock.GetUtcNow();
        // Les invitations expirées ou non consommées du même nom sont remplacées.
        foreach (var old in S.Invitations.Where(i => !i.Consumed && (i.PeerName.Equals(peerName, StringComparison.OrdinalIgnoreCase) || i.ExpiresUtc <= now)).ToList())
        {
            SecretStore.Delete(old.Id);
            S.Invitations.Remove(old);
        }

        var used = S.Peers.Select(p => p.TunnelIp).Concat(S.Invitations.Where(i => !i.Consumed).Select(i => i.TunnelIp));
        var ip = fixedIp ?? TunnelConfigs.NextFreeIp(Subnet, used);
        var psk = _wg.GeneratePresharedKey();
        var invitation = new ServerInvitation
        {
            InvitationId = Context.NewId(),
            PeerName = peerName,
            ServerPublicKey = new WgPublicKey(S.ServerPublicKey),
            EndpointHost = S.EndpointHost,
            EndpointPort = S.ListenPort,
            ServerTunnelIp = TunnelConfigs.ServerIp(Subnet),
            ClientTunnelIp = ip,
            TunnelSubnet = Subnet.ToString(),
            RdpPort = SystemInfo.RdpPort(),
            PresharedKey = psk,
            CreatedUtc = now,
            ExpiresUtc = now.AddDays(ctx.Config.Server.InvitationValidityDays),
        };

        var passphrase = AskPairingPassphrase();
        var json = PairingFile.WriteServer(invitation, passphrase);
        var path = ResolveOutput(output, PairingFile.ServerFileName);
        SecretStore.Save(invitation.InvitationId, psk);
        S.Invitations.Add(new InvitationRecord
        {
            Id = invitation.InvitationId,
            PeerName = peerName,
            TunnelIp = ip,
            CreatedUtc = now,
            ExpiresUtc = invitation.ExpiresUtc,
        });
        ctx.Save();
        File.WriteAllText(path, json);
        ctx.Log.Info($"Invitation {invitation.InvitationId} créée pour « {peerName} » ({ip}), valable jusqu'au {invitation.ExpiresUtc:yyyy-MM-dd}.");
        ctx.Ui.Show("Fichier d'appairage serveur créé (SENSIBLE)",
        [
            $"Fichier : {path}",
            $"Pair : {peerName} — IP dans le tunnel : {ip}",
            $"Empreinte de la clé du serveur (à comparer sur le client) : {invitation.ServerPublicKey.Fingerprint}",
            string.Create(CultureInfo.InvariantCulture, $"Valable jusqu'au {invitation.ExpiresUtc.ToLocalTime():dd/MM/yyyy HH:mm}."),
            "Ce fichier contient la clé pré-partagée (chiffrée par votre phrase de passe).",
            "→ Transférez-le sur une CLÉ USB, jamais par e-mail ni messagerie.",
            "→ Communiquez la phrase de passe par un autre canal (de vive voix, papier).",
            "→ Supprimez le fichier de la clé USB et de ce PC après l'appairage.",
        ]);
        OfferWipe(path);
        return path;
    }

    /// <summary>Ajoute (ou met à jour) le pair décrit par un fichier client, puis redémarre le tunnel.</summary>
    public void AddPeer(string clientFile)
    {
        RequireServer();
        var json = File.ReadAllText(clientFile);
        var invitationId = PairingFile.PeekClientInvitationId(json);
        var invitation = S.Invitations.FirstOrDefault(i => i.Id == invitationId)
            ?? throw new OperationException("Ce fichier client ne correspond à aucune invitation de ce serveur.");
        var conf = WireGuardOps.ReadConf(Tunnel);
        var psk = SecretStore.Load(invitationId)
            ?? conf.Peers.FirstOrDefault(p => S.Peers.Any(sp => sp.InvitationId == invitationId && sp.PublicKey == p.PublicKey.Value))?.PresharedKey
            ?? throw new OperationException("Clé pré-partagée de cette invitation introuvable (invitation révoquée ?). Créez une nouvelle invitation.");
        var response = PairingFile.ReadClient(json, psk);
        if (response.ClientTunnelIp != invitation.TunnelIp)
        {
            throw new OperationException("L'adresse IP déclarée par le client ne correspond pas à l'invitation.");
        }

        if (!invitation.Consumed && invitation.ExpiresUtc < ctx.Clock.GetUtcNow())
        {
            throw new OperationException("Invitation expirée : créez-en une nouvelle (invite).");
        }

        if (conf.Peers.Any(p => p.PublicKey == response.ClientPublicKey && !p.AllowedIps.Contains(invitation.TunnelIp + "/32")))
        {
            throw new OperationException("Cette clé publique est déjà utilisée par un autre pair.");
        }

        ctx.Ui.Info($"Clé publique du client : empreinte {response.ClientPublicKey.Fingerprint} (comparez avec l'écran du client).");
        if (ctx.DryRun)
        {
            ctx.Ui.Info($"[à faire] Ajout du pair « {invitation.PeerName} » ({invitation.TunnelIp}) et redémarrage du tunnel.");
            return;
        }

        var peers = conf.Peers
            .Where(p => !p.AllowedIps.Contains(invitation.TunnelIp + "/32"))
            .Select(p => new ServerPeer(p.Name, p.PublicKey, p.PresharedKey!, p.AllowedIps[0].Split('/')[0]))
            .Append(new ServerPeer(invitation.PeerName, response.ClientPublicKey, psk, invitation.TunnelIp))
            .ToList();
        _wg.WriteConf(Tunnel, TunnelConfigs.Server(conf.Interface.PrivateKey, Subnet, S.ListenPort, peers));
        S.Peers.RemoveAll(p => p.TunnelIp == invitation.TunnelIp);
        S.Peers.Add(new PeerRecord
        {
            Name = invitation.PeerName,
            PublicKey = response.ClientPublicKey.Value,
            TunnelIp = invitation.TunnelIp,
            InvitationId = invitationId,
            AddedUtc = ctx.Clock.GetUtcNow(),
        });
        invitation.Consumed = true;
        SecretStore.Delete(invitationId);
        ctx.Save();
        _wg.RestartTunnel(Tunnel);
        ctx.Ui.Info($"Pair « {invitation.PeerName} » ajouté ({invitation.TunnelIp}). Attente du premier handshake (60 s max)…");
        var handshake = WaitForHandshake(response.ClientPublicKey.Value, TimeSpan.FromSeconds(60));
        if (handshake is null)
        {
            ctx.Ui.Warn("Pas encore de handshake : vérifiez que le tunnel est activé sur le client et que la box redirige bien le port UDP.");
        }
        else
        {
            ctx.Ui.Info($"Handshake réussi à {handshake.Value.ToLocalTime():HH:mm:ss}. Le tunnel est opérationnel.");
        }

        OfferWipe(clientFile);
    }

    public void RevokePeer(string name)
    {
        RequireServer();
        var record = S.Peers.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        var pending = S.Invitations.Where(i => !i.Consumed && i.PeerName.Equals(name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (record is null && pending.Count == 0)
        {
            throw new OperationException($"Pair ou invitation « {name} » introuvable.");
        }

        if (ctx.DryRun)
        {
            ctx.Ui.Info($"[à faire] Révocation de « {name} » et redémarrage du tunnel.");
            return;
        }

        foreach (var inv in pending)
        {
            SecretStore.Delete(inv.Id);
            S.Invitations.Remove(inv);
        }

        if (record is not null)
        {
            var conf = WireGuardOps.ReadConf(Tunnel);
            var peers = conf.Peers.Where(p => p.PublicKey.Value != record.PublicKey)
                .Select(p => new ServerPeer(p.Name, p.PublicKey, p.PresharedKey!, p.AllowedIps[0].Split('/')[0])).ToList();
            _wg.WriteConf(Tunnel, TunnelConfigs.Server(conf.Interface.PrivateKey, Subnet, S.ListenPort, peers));
            S.Peers.Remove(record);
            ctx.Save();
            _wg.RestartTunnel(Tunnel);
        }

        ctx.Save();
        ctx.Ui.Info($"« {name} » révoqué : sa clé ne peut plus établir le tunnel.");
    }

    /// <summary>Rotation des clés du serveur : tous les pairs doivent être réappairés (nouvelles invitations).</summary>
    public void RotateServerKeys(string? outputDir)
    {
        RequireServer();
        var names = S.Peers.Select(p => (p.Name, p.TunnelIp)).ToList();
        if (!ctx.Ui.Confirm($"La rotation des clés du serveur coupe les {names.Count} pair(s) jusqu'à leur réappairage (join sur chaque client). Continuer ?"))
        {
            return;
        }

        if (ctx.DryRun)
        {
            ctx.Ui.Info("[à faire] Nouvelle paire de clés serveur, retrait des pairs, nouvelles invitations.");
            return;
        }

        var kp = _wg.GenerateKeyPair();
        _wg.WriteConf(Tunnel, TunnelConfigs.Server(kp.PrivateKey, Subnet, S.ListenPort, []));
        S.ServerPublicKey = kp.PublicKey.Value;
        S.Peers.Clear();
        foreach (var inv in S.Invitations.Where(i => !i.Consumed))
        {
            SecretStore.Delete(inv.Id);
        }

        S.Invitations.Clear();
        ctx.Save();
        _wg.RestartTunnel(Tunnel);
        ctx.Ui.Info($"Nouvelle clé du serveur : empreinte {kp.PublicKey.Fingerprint}.");
        foreach (var (name, ip) in names)
        {
            var file = outputDir is null ? null : Path.Combine(outputDir, $"pairing-server-{name}.sdpair");
            Invite(name, file, reuseIp: true, fixedIp: ip);
        }
    }

    /// <summary>Rotation pour un pair : nouvelle PSK et nouvelle invitation (le client refait « join »).</summary>
    public void RotatePeer(string name, string? output)
    {
        RequireServer();
        var record = S.Peers.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            ?? throw new OperationException($"Pair « {name} » introuvable.");
        var ip = record.TunnelIp;
        RevokePeer(name);
        if (!ctx.DryRun)
        {
            Invite(name, output, fixedIp: ip);
        }
    }

    public IReadOnlyList<string> ListPeers()
    {
        RequireServer();
        var lines = new List<string>();
        var hs = WireGuardOps.IsInstalled ? _wg.LatestHandshakes(Tunnel) : new Dictionary<string, DateTimeOffset?>();
        foreach (var p in S.Peers)
        {
            var last = hs.TryGetValue(p.PublicKey, out var t) && t is not null ? t.Value.ToLocalTime().ToString("dd/MM HH:mm:ss", CultureInfo.InvariantCulture) : "jamais";
            lines.Add($"{p.Name,-16} {p.TunnelIp,-14} empreinte {WgKeyFormat.Fingerprint(p.PublicKey)}  dernier handshake : {last}");
        }

        foreach (var i in S.Invitations.Where(i => !i.Consumed))
        {
            lines.Add(string.Create(CultureInfo.InvariantCulture, $"{i.PeerName,-16} {i.TunnelIp,-14} invitation en attente (expire le {i.ExpiresUtc.ToLocalTime():dd/MM HH:mm})"));
        }

        return lines.Count > 0 ? lines : ["Aucun pair."];
    }

    // =====================================================================================
    // Comptes, durcissement, TSplus
    // =====================================================================================

    public void Accounts(Func<string, SensitiveText> passwordFor)
    {
        ArgumentNullException.ThrowIfNull(passwordFor);
        var accounts = new Accounts(ctx.Log);
        var policies = new Policies(ctx.Log, ctx.Runner);
        var pp = ctx.Config.Server.PasswordPolicy;
        var steps = new List<IStep>
        {
            new Step("pwd-policy", string.Create(CultureInfo.InvariantCulture,
                    $"Stratégie : mot de passe ≥ {pp.MinLength} caractères, complexité, verrouillage après {pp.LockoutThreshold} échecs ({pp.LockoutDurationMinutes} min)"),
                () => policies.SystemAccessMatches(pp) ? StepCheck.Ok() : StepCheck.Change(),
                () => policies.ApplySystemAccess(pp, ctx.State)),
        };
        foreach (var u in ctx.Config.Server.Users)
        {
            steps.Add(new Step("user:" + u.Name, $"Compte local « {u.Name} »",
                () => Sys.Accounts.Exists(u.Name) ? StepCheck.Ok("existant") : u.Create ? StepCheck.Change("à créer") : throw new OperationException($"Le compte « {u.Name} » n'existe pas (create = false)."),
                () =>
                {
                    SensitiveText pwd;
                    while (true)
                    {
                        pwd = passwordFor(u.Name);
                        var problems = Sys.Accounts.CheckPassword(pwd, u.Name, pp.MinLength);
                        if (problems.Count == 0)
                        {
                            break;
                        }

                        ctx.Ui.Warn("Mot de passe refusé : " + string.Join(" ; ", problems));
                    }

                    accounts.Create(u.Name, pwd, u.FullName);
                    ctx.State.RecordOriginal("account:" + u.Name, "account-created", new Dictionary<string, string?> { ["name"] = u.Name });
                }));
            steps.Add(new Step("rdu:" + u.Name, $"« {u.Name} » membre de « Utilisateurs du Bureau à distance » (S-1-5-32-555)",
                () => ctx.DryRun && !Sys.Accounts.Exists(u.Name) ? StepCheck.Change() : Sys.Accounts.IsInGroup(u.Name, HardeningPlan.RemoteDesktopUsersSid) ? StepCheck.Ok() : StepCheck.Change(),
                () => accounts.AddToGroup(u.Name, HardeningPlan.RemoteDesktopUsersSid)));
        }

        ctx.Run(steps);
    }

    public void Harden()
    {
        var policies = new Policies(ctx.Log, ctx.Runner);
        var cfg = ctx.Config.Server;
        var steps = new List<IStep>();
        foreach (var spec in HardeningPlan.RdpPolicies(cfg))
        {
            steps.Add(new Step("reg:" + spec.Key, $"RDP : {spec.Purpose} ({spec.Name} = {Convert.ToString(spec.Value, CultureInfo.InvariantCulture)})",
                () => RegistryOps.Matches(spec) ? StepCheck.Ok() : StepCheck.Change(),
                () => RegistryOps.Set(spec, ctx.State)));
        }

        steps.Add(new Step("audit", "Audit des ouvertures de session (succès et échecs : 4624, 4625, verrouillages)",
            () => policies.AuditMatches(HardeningPlan.AuditSubcategories.Select(a => a.Guid)) ? StepCheck.Ok() : StepCheck.Change(),
            () => policies.EnableAudit(HardeningPlan.AuditSubcategories.Select(a => a.Guid), ctx.State)));
        steps.Add(new Step("seclog", "Taille du journal Sécurité ≥ 256 Mo",
            () => Policies.SecurityLogMaxSize() >= HardeningPlan.SecurityLogMinBytes ? StepCheck.Ok() : StepCheck.Change(),
            () => policies.EnsureSecurityLogSize(HardeningPlan.SecurityLogMinBytes, ctx.State)));
        steps.Add(new Step("rcmlog", "Journal des connexions RDP (événement 1149) actif",
            () => policies.IsLogEnabled(HardeningPlan.RemoteConnectionManagerLog) ? StepCheck.Ok() : StepCheck.Change(),
            () => policies.EnableLog(HardeningPlan.RemoteConnectionManagerLog, ctx.State)));
        steps.Add(new Step("w32time", $"Synchronisation horaire Windows (W32Time, {cfg.NtpServer})",
            () => Policies.TimeSyncConfigured(cfg.NtpServer) ? StepCheck.Ok() : StepCheck.Change(),
            () => policies.ConfigureTimeSync(cfg.NtpServer, ctx.State)));
        ctx.Run(steps);

        if (RegistryOps.ReadDword(HardeningPlan.TsPolicyPath, HardeningPlan.PromptForPasswordValue) == 1
            || RegistryOps.ReadDword(HardeningPlan.RdpTcpPath, HardeningPlan.PromptForPasswordValue) == 1)
        {
            ctx.Ui.Warn("La stratégie « Toujours demander le mot de passe à la connexion » (fPromptForPassword) est active : elle provoque une double saisie avec NLA et multiOTP. Elle n'est pas modifiée par SecureDesk (voir RECETTE).");
        }

        var bl = Checks.BitLocker();
        if (bl.Level != CheckLevel.Ok)
        {
            ctx.Ui.Warn(bl.Detail + ". SecureDesk ne l'active jamais automatiquement.");
        }
    }

    public void Tsplus(bool waitForManualInstall)
    {
        var ts = new TsplusOps(ctx.Log, ctx.Runner);
        var status = TsplusOps.Detect();
        if (!status.Installed)
        {
            var setup = ctx.Config.Installers.TsplusSetup;
            if (ctx.Config.Installers.TsplusSilent && setup is not null && !ctx.DryRun)
            {
                ts.InstallSilently(setup);
            }
            else
            {
                ctx.Ui.Show("Installation de TSplus Remote Access (manuelle)", TsplusOps.ManualInstallInstructions());
                if (waitForManualInstall && !ctx.DryRun)
                {
                    while (!TsplusOps.Detect().Installed)
                    {
                        if (!ctx.Ui.Confirm("TSplus est-il installé et activé ? (Oui = revérifier, Non = arrêter ici)", true))
                        {
                            throw new OperationException("TSplus non installé : reprenez cette étape plus tard (tsplus-check).");
                        }
                    }
                }
            }

            status = TsplusOps.Detect();
        }

        ctx.Ui.Info(status.ToString());
        if (!status.Installed)
        {
            return;
        }

        if (ctx.Config.Server.StopTsplusWebServer && TsplusOps.WebServerListening(ctx.Config.Server.ExtraProtectedTcpPorts))
        {
            ctx.Run(
            [
                new Step("tsplus-web", "Arrêt du serveur web TSplus (portail non utilisé ; il relaie aussi RDP) — AdminTool.exe /webstop",
                    () => TsplusOps.WebServerListening(ctx.Config.Server.ExtraProtectedTcpPorts) ? StepCheck.Change() : StepCheck.Ok(),
                    () =>
                    {
                        ctx.State.RecordOriginal("tsplus:web", "tsplus-web", new Dictionary<string, string?> { ["wasRunning"] = "true" });
                        ts.StopWebServer();
                    }),
            ]);
        }

        if (ts.TsplusTwoFactorHasUsers() == true)
        {
            ctx.Ui.Warn("Le module 2FA de TSplus contient des utilisateurs : il n'est pas utilisé par SecureDesk et peut provoquer des invites supplémentaires. Désactivez-le dans TSplus (aucune modification automatique).");
        }

        ctx.Ui.Show("Réglages TSplus à vérifier dans l'AdminTool", TsplusOps.SecuritySettingsInstructions());
    }

    // =====================================================================================
    // Rapport
    // =====================================================================================

    public IReadOnlyList<string> BoxChecklist()
    {
        var lan = SystemInfo.DetectLan();
        var lanIp = lan?.Address ?? "(IP LAN du PC serveur)";
        var port = S.ListenPort > 0 ? S.ListenPort.ToString(CultureInfo.InvariantCulture) : "(port UDP choisi)";
        var endpoint = string.IsNullOrEmpty(S.EndpointHost) ? ctx.Config.Server.EndpointHost : S.EndpointHost;
        var dynamicName = !Ipv4Cidr.TryParseAddress(endpoint, out _);
        return
        [
            $"1. Redirection de port : UDP {port} (externe) → {lanIp} port UDP {port} (interne). AUCUN autre port.",
            "2. Ne redirigez JAMAIS les ports 3389, 80, 443 ni la « DMZ » vers ce PC. Désactivez l'UPnP de la box si possible.",
            $"3. Réservation DHCP (bail statique) : associez l'adresse {lanIp} à ce PC ({SystemInfo.MachineName}){(lan is null ? string.Empty : ", interface " + lan.InterfaceName)}.",
            dynamicName
                ? $"4. DDNS : configurez le nom « {endpoint} » dans la box (ou un client DDNS) pour qu'il suive l'IP publique du bureau."
                : $"4. Endpoint en IP fixe ({endpoint}). Si l'IP publique change, utilisez un nom DDNS et réappairez les clients.",
            "5. Test depuis l'extérieur (4G) : seul le port UDP doit répondre ; RDP/TSplus doivent être injoignables (voir RECETTE).",
        ];
    }

    public IReadOnlyList<string> Report()
    {
        var lines = new List<string> { "=== Rapport SecureDesk (serveur) ===" };
        lines.AddRange(Diagnostics.Server(ctx).Select(c => c.ToString()));
        lines.Add(string.Empty);
        lines.Add("Pairs :");
        lines.AddRange(ctx.State.Server is null ? ["(serveur non initialisé)"] : ListPeers().Select(l => "  " + l));
        lines.Add(string.Empty);
        lines.Add("Configuration de la box :");
        lines.AddRange(BoxChecklist().Select(l => "  " + l));
        return [.. lines.Select(Redactor.Redact)];
    }

    // =====================================================================================
    // Aides
    // =====================================================================================

    private void RequireServer()
    {
        if (ctx.State.Server is null || string.IsNullOrEmpty(ctx.State.Server.ServerPublicKey))
        {
            throw new OperationException("Serveur non initialisé : lancez d'abord « init ».");
        }
    }

    private SensitiveText AskPairingPassphrase()
    {
        var suggestion = PassphrasePolicy.Generate();
        ctx.Ui.ShowSecretsOnce("Phrase de passe proposée pour chiffrer le fichier d'appairage",
        [
            suggestion.Reveal(),
            "Notez-la sur papier : elle sera demandée sur le PC client. Vous pouvez aussi saisir la vôtre (14 caractères minimum).",
        ]);
        while (true)
        {
            var p = ctx.Ui.AskSecret("Phrase de passe (laisser vide pour utiliser la proposition)", confirm: false);
            if (p.IsEmpty)
            {
                return suggestion;
            }

            var confirm = ctx.Ui.AskSecret("Confirmez la phrase de passe", confirm: false);
            if (!p.Equals(confirm))
            {
                ctx.Ui.Warn("Les deux saisies diffèrent.");
                continue;
            }

            var problems = PassphrasePolicy.Check(p);
            if (problems.Count == 0)
            {
                return p;
            }

            ctx.Ui.Warn(string.Join(" ", problems));
        }
    }

    private static string ResolveOutput(string? output, string defaultName)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), defaultName);
        }

        return Directory.Exists(output) ? Path.Combine(output, defaultName) : Path.GetFullPath(output);
    }

    private void OfferWipe(string path)
    {
        if (ctx.AssumeYes)
        {
            ctx.Ui.Info($"Pensez à supprimer « {path} » une fois transféré (non supprimé automatiquement en mode --yes).");
            return;
        }

        if (File.Exists(path) && ctx.Ui.Confirm($"Le fichier « {Path.GetFileName(path)} » a-t-il bien été copié là où il doit aller ? Le supprimer maintenant de cet emplacement ({path}) ?"))
        {
            SecureFiles.BestEffortWipe(path);
            ctx.Ui.Info("Fichier supprimé. Sur un SSD ou une clé USB, l'effacement physique n'est pas garanti : formatez la clé USB après usage.");
        }
    }

    private DateTimeOffset? WaitForHandshake(string publicKey, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (_wg.LatestHandshakes(Tunnel).TryGetValue(publicKey, out var t) && t is not null)
            {
                return t;
            }

            Thread.Sleep(2000);
        }

        return null;
    }

    private void EnsureBlockingChecksPass(IReadOnlyList<CheckItem> checks)
    {
        foreach (var c in checks)
        {
            if (c.Level == CheckLevel.Ok)
            {
                ctx.Ui.Info(c.ToString());
            }
            else
            {
                ctx.Ui.Warn(c.ToString());
            }
        }

        // L'horloge n'est bloquante que pour l'activation du 2FA, pas pour le tunnel.
        var blocking = checks.Where(c => c.Level == CheckLevel.Blocking && c.Name != "Horloge").ToList();
        if (blocking.Count > 0)
        {
            throw new OperationException("Pré-vérifications bloquantes : " + string.Join(" ; ", blocking.Select(b => b.Name + " — " + b.Detail)));
        }
    }
}

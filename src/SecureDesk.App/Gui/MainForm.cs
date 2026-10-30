using System.Globalization;
using SecureDesk.Core.Config;
using SecureDesk.Core.Logging;
using SecureDesk.Core.Net;
using SecureDesk.Core.State;
using SecureDesk.Windows.Ops;
using SecureDesk.Windows.Sys;

namespace SecureDesk.App.Gui;

/// <summary>Une page de l'assistant.</summary>
internal sealed class WizardPage(string title, string help, Action<FlowLayoutPanel> build, Func<bool>? canLeave = null)
{
    public string Title { get; } = title;
    public string Help { get; } = help;
    public Action<FlowLayoutPanel> Build { get; } = build;
    public Func<bool> CanLeave { get; } = canLeave ?? (() => true);
}

/// <summary>Assistant graphique : choix du rôle puis pages successives. Chaque action appelle les mêmes opérations que la CLI.</summary>
internal sealed class MainForm : Form
{
    private readonly SecureDeskConfig _config;
    private readonly RichTextBox _log;
    private readonly Label _title;
    private readonly Label _help;
    private readonly FlowLayoutPanel _content;
    private readonly Button _back;
    private readonly Button _next;
    private readonly ListBox _steps;
    private readonly CheckBox _dryRun;
    private readonly FileLog _fileLog;
    private List<WizardPage> _pages = [];
    private int _index;
    private bool _busy;

    public MainForm()
    {
        Text = "SecureDesk " + Cli.Commands.Version + " — bureau à distance sécurisé";
        Size = new Size(1100, 760);
        MinimumSize = new Size(900, 640);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10);

        SecureFiles.EnsureProtectedDirectory(SecureFiles.ProgramDataRoot);
        _fileLog = new FileLog(SecureFiles.LogsDir);
        _config = File.Exists(ConfigPath) ? SecureDeskConfig.Load(ConfigPath) : new SecureDeskConfig();
        var state = new FileStateStore(SecureFiles.StatePath).Load();
        if (state.Server is { } s)
        {
            // Reprise : on recharge les paramètres déjà déployés.
            _config.Server.EndpointHost = s.EndpointHost;
            _config.Server.ListenPort = s.ListenPort;
            _config.Server.TunnelSubnet = s.TunnelSubnet;
        }

        _steps = new ListBox { Dock = DockStyle.Left, Width = 230, IntegralHeight = false, Enabled = false, BorderStyle = BorderStyle.None, BackColor = SystemColors.Control };
        _title = new Label { Dock = DockStyle.Top, Height = 40, Font = new Font("Segoe UI Semibold", 15), Padding = new Padding(8, 6, 0, 0) };
        _help = new Label { Dock = DockStyle.Top, Height = 64, Padding = new Padding(10, 4, 10, 4), ForeColor = Color.DimGray };
        _content = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(12) };
        _log = new RichTextBox { Dock = DockStyle.Bottom, Height = 190, ReadOnly = true, Font = new Font(FontFamily.GenericMonospace, 9), BackColor = Color.White };
        _back = new Button { Text = "< Précédent", AutoSize = true };
        _next = new Button { Text = "Suivant >", AutoSize = true };
        _dryRun = new CheckBox { Text = "Simulation (--dry-run : rien n'est modifié)", AutoSize = true, Padding = new Padding(0, 6, 20, 0) };
        _back.Click += (_, _) => Go(_index - 1);
        _next.Click += (_, _) =>
        {
            if (_pages[_index].CanLeave())
            {
                Go(_index + 1);
            }
        };
        var nav = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
        nav.Controls.AddRange([_next, _back, _dryRun]);

        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(_content);
        right.Controls.Add(_help);
        right.Controls.Add(_title);
        right.Controls.Add(nav);
        Controls.Add(right);
        Controls.Add(_steps);
        Controls.Add(_log);
        ShowRoleChoice(state);
    }

    private static string ConfigPath => Path.Combine(SecureFiles.ProgramDataRoot, "assistant.json");

    // ------------------------------------------------------------------ Navigation

    private void ShowRoleChoice(SecureDeskState state)
    {
        _pages =
        [
            new("Bienvenue", "SecureDesk installe un accès bureau à distance sécurisé : tunnel WireGuard + TSplus (sessions multiples) + double authentification multiOTP. Choisissez le rôle de CE PC.", p =>
            {
                var current = state.Role switch
                {
                    "server" => "Ce PC est déjà configuré comme SERVEUR.",
                    "client" => "Ce PC est déjà configuré comme CLIENT.",
                    _ => "Ce PC n'est pas encore configuré.",
                };
                p.Controls.Add(Para(current));
                p.Controls.Add(BigButton("PC du bureau = SERVEUR\n(Windows 11 Pro, allumé en permanence)", () => StartRole(server: true)));
                p.Controls.Add(BigButton("PC personnel = CLIENT\n(pour se connecter au bureau)", () => StartRole(server: false)));
                p.Controls.Add(BigButton("Maintenance : diagnostic, désinstallation", StartMaintenance));
            }),
        ];
        _steps.Items.Clear();
        Go(0);
    }

    private void StartRole(bool server)
    {
        _pages = server ? ServerPages() : ClientPages();
        _pages.Add(MaintenancePage());
        _steps.Items.Clear();
        foreach (var p in _pages)
        {
            _steps.Items.Add(p.Title);
        }

        Go(0);
    }

    private void StartMaintenance()
    {
        _pages = [MaintenancePage()];
        _steps.Items.Clear();
        _steps.Items.Add(_pages[0].Title);
        Go(0);
    }

    private void Go(int index)
    {
        if (index < 0 || index >= _pages.Count || _busy)
        {
            return;
        }

        SaveAssistantConfig();
        _index = index;
        var page = _pages[index];
        _title.Text = page.Title;
        _help.Text = page.Help;
        _content.SuspendLayout();
        _content.Controls.Clear();
        page.Build(_content);
        _content.ResumeLayout();
        if (_steps.Items.Count > index)
        {
            _steps.SelectedIndex = index;
        }

        _back.Enabled = index > 0;
        _next.Enabled = index < _pages.Count - 1;
    }

    private void SaveAssistantConfig()
    {
        try
        {
            SecureFiles.WriteProtected(ConfigPath, _config.ToJson());
        }
        catch (IOException)
        {
        }
    }

    // ------------------------------------------------------------------ Exécution

    private Context NewContext() => new(new CompositeLog(_fileLog, new UiLog(this)), new GuiUi(this, AppendLog), _config, new FileStateStore(SecureFiles.StatePath), _dryRun.Checked);

    /// <summary>Exécute une opération en arrière-plan (l'interface reste réactive ; les dialogues sont ramenés sur le thread UI).</summary>
    private async void RunOp(string label, Action<Context> op, Action? after = null)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        UseWaitCursor = true;
        _content.Enabled = _back.Enabled = _next.Enabled = false;
        AppendLog($"▶ {label}{(_dryRun.Checked ? " (simulation)" : string.Empty)}", Color.SteelBlue);
        try
        {
            await Task.Run(() => op(NewContext()));
            AppendLog($"✔ {label} : terminé", Color.ForestGreen);
            after?.Invoke();
        }
#pragma warning disable CA1031 // Toute erreur est affichée à l'utilisateur et journalisée.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _fileLog.Error(ex.ToString());
            AppendLog("✖ " + ex.Message, Color.Firebrick);
            MessageBox.Show(this, ex.Message + "\n\nJournal : " + _fileLog.Path, "SecureDesk", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _busy = false;
            UseWaitCursor = false;
            _content.Enabled = true;
            _back.Enabled = _index > 0;
            _next.Enabled = _index < _pages.Count - 1;
        }
    }

    internal void AppendLog(string message, Color color)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => AppendLog(message, color));
            return;
        }

        _log.SelectionStart = _log.TextLength;
        _log.SelectionColor = color;
        _log.AppendText(Redactor.Redact(message) + Environment.NewLine);
        _log.ScrollToCaret();
    }

    private sealed class UiLog(MainForm form) : ILog
    {
        public void Write(LogLevel level, string message)
        {
            if (level >= LogLevel.Warning)
            {
                form.AppendLog(message, level == LogLevel.Error ? Color.Firebrick : Color.DarkOrange);
            }
        }
    }

    // ------------------------------------------------------------------ Pages serveur

    private List<WizardPage> ServerPages()
    {
        var s = _config.Server;
        return
        [
            new("1. Pré-vérifications", "Contrôle de l'édition Windows, des droits, du redémarrage en attente, des ressources, de TSplus, du réseau, du type de session et de l'heure.", p =>
            {
                var list = ResultList();
                p.Controls.Add(ActionButton("Lancer les vérifications", () => RunOp("Pré-vérifications", ctx => Fill(list, Checks.Server(ctx)))));
                p.Controls.Add(list);
            }),
            new("2. Réseau et tunnel", "Paramètres du tunnel WireGuard. Seul le port UDP choisi sera redirigé par la box vers ce PC.", p =>
            {
                var endpoint = Field(p, "Adresse publique du bureau (IP fixe ou nom DDNS, ex. monbureau.ddns.net) :", s.EndpointHost, v => s.EndpointHost = v);
                var port = Field(p, "Port UDP WireGuard (aléatoire, non standard) :", (s.ListenPort ?? PortSuggester.Suggest(SystemInfo.IsUdpPortInUse)).ToString(CultureInfo.InvariantCulture),
                    v => s.ListenPort = int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : null);
                s.ListenPort ??= int.Parse(port.Text, CultureInfo.InvariantCulture);
                p.Controls.Add(ActionButton("Proposer un autre port", () => port.Text = PortSuggester.Suggest(SystemInfo.IsUdpPortInUse).ToString(CultureInfo.InvariantCulture)));
                Field(p, "Sous-réseau du tunnel (serveur = 1re adresse) :", s.TunnelSubnet, v => s.TunnelSubnet = v);
                var lan = SystemInfo.DetectLan();
                Check(p, $"Autoriser aussi l'accès RDP depuis le réseau local {(lan is null ? string.Empty : "(" + lan.Subnet + ")")} — utilisateur sur place via le LAN", s.AllowLan, v =>
                {
                    s.AllowLan = v;
                    s.LanSubnet = v ? lan?.Subnet.ToString() : null;
                });
                p.Controls.Add(Para("Rappel : une connexion RDP depuis le LAN compte comme « à distance » et demandera le code TOTP une fois le 2FA activé."));
                _ = endpoint;
            }, () => Validate(_config.ValidateServer().Where(e => !e.Contains("compte", StringComparison.OrdinalIgnoreCase)).ToList())),
            new("3. TSplus", "SecureDesk ne télécharge pas TSplus et n'active jamais la licence. Il détecte TSplus et vous guide.", p =>
            {
                var status = Para(Windows.Tsplus.TsplusOps.Detect().ToString());
                p.Controls.Add(status);
                p.Controls.Add(Para(string.Join(Environment.NewLine, Windows.Tsplus.TsplusOps.ManualInstallInstructions())));
                p.Controls.Add(ActionButton("Revérifier", () => status.Text = Windows.Tsplus.TsplusOps.Detect().ToString()));
                p.Controls.Add(ActionButton("Installation silencieuse (/verysilent) avec l'installeur fourni…", () =>
                {
                    using var dlg = new OpenFileDialog { Filter = "Installeur TSplus|*.exe", Title = "Setup-TSplus.exe" };
                    if (dlg.ShowDialog(this) == DialogResult.OK)
                    {
                        _config.Installers.TsplusSetup = dlg.FileName;
                        _config.Installers.TsplusSilent = true;
                        RunOp("Installation de TSplus", ctx => new ServerOps(ctx).Tsplus(waitForManualInstall: false), () => status.Text = Windows.Tsplus.TsplusOps.Detect().ToString());
                    }
                }));
                p.Controls.Add(Para(string.Join(Environment.NewLine, Windows.Tsplus.TsplusOps.SecuritySettingsInstructions())));
            }, () => Windows.Tsplus.TsplusOps.Detect().Installed || Ask("TSplus n'est pas détecté. Continuer quand même (vous l'installerez plus tard) ?")),
            new("4. Comptes", "Deux comptes Windows distincts pour deux sessions simultanées. Les mots de passe seront demandés au déploiement (jamais enregistrés).", p =>
            {
                while (s.Users.Count < 2)
                {
                    s.Users.Add(new UserSpec { Name = string.Empty });
                }

                for (var i = 0; i < 2; i++)
                {
                    var u = s.Users[i];
                    Field(p, $"Compte n° {i + 1} :", u.Name, v => u.Name = v.Trim());
                    Check(p, "Créer ce compte s'il n'existe pas", u.Create, v => u.Create = v);
                }

                Field(p, "Verrouiller un compte après N échecs :", s.PasswordPolicy.LockoutThreshold.ToString(CultureInfo.InvariantCulture),
                    v => s.PasswordPolicy.LockoutThreshold = int.TryParse(v, out var n) ? n : 5);
            }, () => Validate(_config.ValidateServer().Where(e => e.Contains("compte", StringComparison.OrdinalIgnoreCase) || e.Contains("verrouillage", StringComparison.OrdinalIgnoreCase)).ToList())
                     && (s.Users.All(u => u.Name.Length > 0) || Validate(["Indiquez les deux noms de comptes."]))),
            new("5. Sécurité RDP", "NLA, TLS et chiffrement élevé sont imposés. Les redirections sont désactivées par défaut pour limiter la fuite de données.", p =>
            {
                Check(p, "Autoriser le presse-papiers", s.Redirections.Clipboard, v => s.Redirections.Clipboard = v);
                Check(p, "Autoriser les lecteurs (disques du PC client)", s.Redirections.Drives, v => s.Redirections.Drives = v);
                Check(p, "Autoriser les imprimantes", s.Redirections.Printers, v => s.Redirections.Printers = v);
                Field(p, "Fermer les sessions inactives après (minutes) :", s.IdleTimeoutMinutes.ToString(CultureInfo.InvariantCulture), v => s.IdleTimeoutMinutes = int.TryParse(v, out var n) ? n : 30);
                Field(p, "Fermer les sessions déconnectées après (minutes) :", s.DisconnectedTimeoutMinutes.ToString(CultureInfo.InvariantCulture), v => s.DisconnectedTimeoutMinutes = int.TryParse(v, out var n) ? n : 60);
            }, () => Validate(_config.ValidateServer())),
            new("6. Déploiement", "Installe WireGuard, crée le tunnel, le pare-feu, les comptes et le durcissement, puis exporte le fichier d'appairage CHIFFRÉ. Prévoyez une clé USB.", p =>
            {
                p.Controls.Add(Para($"Endpoint {s.EndpointHost}:{s.ListenPort} — tunnel {s.TunnelSubnet} — comptes {string.Join(", ", s.Users.Select(u => u.Name))} — LAN {(s.AllowLan ? s.LanSubnet : "non")}"));
                p.Controls.Add(ActionButton("Déployer", () =>
                {
                    var output = ChooseSave("pairing-server.sdpair", "Où enregistrer le fichier d'appairage (clé USB recommandée) ?");
                    if (output is null)
                    {
                        return;
                    }

                    RunOp("Déploiement du serveur", ctx =>
                    {
                        var ops = new ServerOps(ctx);
                        ops.Init(output);
                        ops.Accounts(name => ctx.Ui.AskSecret($"Mot de passe du nouveau compte « {name} » (14 caractères min., 3 types de caractères)", confirm: true));
                        ops.Harden();
                        ops.Tsplus(waitForManualInstall: false);
                    });
                }));
                p.Controls.Add(ActionButton("Nouvelle invitation (autre PC client)…", () =>
                {
                    var name = new GuiUi(this, AppendLog).Ask("Nom du nouveau pair (ex. portable)");
                    var output = ChooseSave("pairing-server.sdpair", "Fichier d'invitation");
                    if (!string.IsNullOrWhiteSpace(name) && output is not null)
                    {
                        RunOp("Invitation", ctx => new ServerOps(ctx).Invite(name, output));
                    }
                }));
            }),
            new("7. Ajout du PC client", "Après « join » sur le PC client, rapportez le fichier pairing-client.sdpair (clé publique uniquement) et importez-le ici.", p =>
            {
                p.Controls.Add(ActionButton("Importer pairing-client.sdpair…", () =>
                {
                    var file = ChooseOpen("Fichier d'appairage client|*.sdpair");
                    if (file is not null)
                    {
                        RunOp("Ajout du pair", ctx => new ServerOps(ctx).AddPeer(file));
                    }
                }));
                var list = ResultList();
                p.Controls.Add(ActionButton("Lister les pairs", () => RunOp("Pairs", ctx => FillText(list, new ServerOps(ctx).ListPeers()))));
                p.Controls.Add(ActionButton("Révoquer un pair…", () =>
                {
                    var name = new GuiUi(this, AppendLog).Ask("Nom du pair à révoquer");
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        RunOp("Révocation", ctx => new ServerOps(ctx).RevokePeer(name));
                    }
                }));
                p.Controls.Add(list);
            }),
            new("8. Box et rapport", "Configurez la box Internet, puis testez la connexion depuis le PC client avant d'activer la double authentification.", p =>
            {
                var list = ResultList();
                p.Controls.Add(ActionButton("Afficher le rapport et la checklist de la box", () => RunOp("Rapport", ctx => FillText(list, new ServerOps(ctx).Report()))));
                p.Controls.Add(ActionButton("Exporter le rapport (sans secret)…", () =>
                {
                    var path = ChooseSave("SecureDesk-rapport.txt", "Rapport");
                    if (path is not null)
                    {
                        RunOp("Export du rapport", ctx => Diagnostics.Export(new ServerOps(ctx).Report(), path));
                    }
                }));
                p.Controls.Add(list);
            }),
            TwoFactorPage(),
        ];
    }

    private WizardPage TwoFactorPage() => new("9. Double authentification", "À faire EN DERNIER, à la console du PC, une fois le tunnel et RDP validés. Ordre : installer → enrôler (au moins un administrateur et tous les comptes RDP) → activer (probatoire) → tester depuis le client → confirmer.", p =>
    {
        var s = _config.Server;
        p.Controls.Add(ActionButton("1. Installer multiOTP (désactivé)", () => RunOp("Installation multiOTP", ctx => new TwoFactorOps(ctx).Install())));
        var accounts = new ComboBox { Width = 300, DropDownStyle = ComboBoxStyle.DropDown };
        accounts.Items.AddRange([.. s.Users.Select(u => u.Name).Where(n => n.Length > 0).Append(Accounts.CurrentUserName()).Distinct(StringComparer.OrdinalIgnoreCase)]);
        p.Controls.Add(Para("Compte Windows à enrôler (QR code affiché une seule fois) :"));
        p.Controls.Add(accounts);
        p.Controls.Add(ActionButton("2. Enrôler ce compte", () =>
        {
            var name = accounts.Text.Trim();
            if (name.Length > 0)
            {
                RunOp("Enrôlement de " + name, ctx => new TwoFactorOps(ctx).Enroll(name));
            }
        }));
        var remote = new RadioButton { Text = "Distant seulement (recommandé : la console reste inchangée)", AutoSize = true, Checked = s.TwoFactor.Scope == TwoFactorScope.RemoteOnly };
        var all = new RadioButton { Text = "Distant et local (la console exige aussi le TOTP)", AutoSize = true, Checked = s.TwoFactor.Scope == TwoFactorScope.RemoteAndLocal };
        remote.CheckedChanged += (_, _) => s.TwoFactor.Scope = remote.Checked ? TwoFactorScope.RemoteOnly : TwoFactorScope.RemoteAndLocal;
        p.Controls.Add(remote);
        p.Controls.Add(all);
        p.Controls.Add(ActionButton("3. Activer (probatoire)", () => RunOp("Activation du 2FA", ctx => new TwoFactorOps(ctx).Enable(s.TwoFactor.Scope))));
        p.Controls.Add(ActionButton("4. Confirmer (après un test réussi depuis le client)", () => RunOp("Confirmation du 2FA", ctx => new TwoFactorOps(ctx).Confirm())));
        p.Controls.Add(ActionButton("Désactiver le 2FA", () => RunOp("Désactivation du 2FA", ctx => new TwoFactorOps(ctx).Disable(false))));
    });

    // ------------------------------------------------------------------ Pages client

    private List<WizardPage> ClientPages() =>
    [
        new("1. Pré-vérifications", "Droits administrateur et chiffrement BitLocker (qui protège la clé privée WireGuard en cas de vol).", p =>
        {
            var list = ResultList();
            p.Controls.Add(ActionButton("Lancer les vérifications", () => RunOp("Pré-vérifications", _ => Fill(list, Checks.Client()))));
            p.Controls.Add(list);
        }),
        new("2. Appairage", "Importez pairing-server.sdpair (clé USB) : vous saisirez la phrase de passe. Les clés de ce PC sont générées ici et la clé privée ne quitte jamais ce PC.", p =>
        {
            Check(p, "Démarrer le tunnel automatiquement avec Windows (sinon : activation manuelle depuis l'icône WireGuard, configuration chiffrée)", _config.Client.AutoStartTunnel, v => _config.Client.AutoStartTunnel = v);
            p.Controls.Add(ActionButton("Importer pairing-server.sdpair…", () =>
            {
                var file = ChooseOpen("Fichier d'appairage serveur|*.sdpair");
                if (file is null)
                {
                    return;
                }

                var output = ChooseSave("pairing-client.sdpair", "Où enregistrer le fichier à rapporter au serveur (clé USB) ?");
                if (output is not null)
                {
                    RunOp("Appairage", ctx => new ClientOps(ctx).Join(file, output));
                }
            }));
        }),
        new("3. Test et raccourci", "Vérifie le tunnel, la connexion RDP à travers le tunnel, et crée le raccourci .rdp (sans mot de passe enregistré).", p =>
        {
            var list = ResultList();
            p.Controls.Add(ActionButton("Tester la connexion", () => RunOp("Test", ctx => Fill(list, new ClientOps(ctx).Test()))));
            p.Controls.Add(ActionButton("Créer le raccourci Bureau à distance", () => RunOp("Raccourci RDP", ctx => new ClientOps(ctx).RdpShortcut())));
            p.Controls.Add(list);
        }),
    ];

    // ------------------------------------------------------------------ Maintenance

    private WizardPage MaintenancePage() => new("Maintenance", "Diagnostic (sans secret) et désinstallation complète (TSplus et comptes conservés sauf demande explicite).", p =>
    {
        var list = ResultList();
        p.Controls.Add(ActionButton("Diagnostic", () => RunOp("Diagnostic", ctx => FillText(list, ctx.State.Role == "client" ? new ClientOps(ctx).Report() : new ServerOps(ctx).Report()))));
        p.Controls.Add(ActionButton("Exporter le diagnostic…", () =>
        {
            var path = ChooseSave("SecureDesk-diagnostic.txt", "Diagnostic");
            if (path is not null)
            {
                RunOp("Export", ctx => Diagnostics.Export(ctx.State.Role == "client" ? new ClientOps(ctx).Report() : new ServerOps(ctx).Report(), path));
            }
        }));
        var removeAccounts = new CheckBox { Text = "Supprimer aussi les comptes créés par SecureDesk", AutoSize = true };
        p.Controls.Add(removeAccounts);
        p.Controls.Add(ActionButton("Désinstaller SecureDesk (rollback complet)", () => RunOp("Désinstallation", ctx => new Uninstaller(ctx).Run(removeAccounts.Checked))));
        p.Controls.Add(list);
    });

    // ------------------------------------------------------------------ Contrôles

    private static Label Para(string text) => new() { Text = text, AutoSize = true, MaximumSize = new Size(800, 0), Padding = new Padding(0, 4, 0, 8) };

    private static Button ActionButton(string text, Action onClick)
    {
        var b = new Button { Text = text, AutoSize = true, Padding = new Padding(8, 4, 8, 4), Margin = new Padding(0, 4, 0, 4) };
        b.Click += (_, _) => onClick();
        return b;
    }

    private static Button BigButton(string text, Action onClick)
    {
        var b = new Button { Text = text, Width = 520, Height = 80, Margin = new Padding(0, 8, 0, 8), Font = new Font("Segoe UI", 11) };
        b.Click += (_, _) => onClick();
        return b;
    }

    private static TextBox Field(FlowLayoutPanel p, string label, string? value, Action<string> onChange)
    {
        p.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(0, 8, 0, 0) });
        var box = new TextBox { Text = value ?? string.Empty, Width = 420 };
        box.TextChanged += (_, _) => onChange(box.Text);
        p.Controls.Add(box);
        return box;
    }

    private static void Check(FlowLayoutPanel p, string label, bool value, Action<bool> onChange)
    {
        var c = new CheckBox { Text = label, Checked = value, AutoSize = true, MaximumSize = new Size(800, 0), Margin = new Padding(0, 6, 0, 0) };
        c.CheckedChanged += (_, _) => onChange(c.Checked);
        p.Controls.Add(c);
    }

    private static ListView ResultList()
    {
        var lv = new ListView { View = View.Details, Width = 800, Height = 260, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable };
        lv.Columns.Add("État", 100);
        lv.Columns.Add("Élément", 200);
        lv.Columns.Add("Détail", 480);
        return lv;
    }

    private void Fill(ListView lv, IReadOnlyList<CheckItem> items) => BeginInvoke(() =>
    {
        lv.Items.Clear();
        foreach (var i in items)
        {
            var row = new ListViewItem([i.Label, i.Name, i.Detail])
            {
                ForeColor = i.Level switch { CheckLevel.Ok => Color.ForestGreen, CheckLevel.Warning => Color.DarkOrange, _ => Color.Firebrick },
            };
            lv.Items.Add(row);
        }
    });

    private void FillText(ListView lv, IReadOnlyList<string> lines) => BeginInvoke(() =>
    {
        lv.Items.Clear();
        foreach (var l in lines)
        {
            lv.Items.Add(new ListViewItem(["", "", l]));
        }
    });

    private bool Validate(IReadOnlyList<string> errors)
    {
        if (errors.Count == 0)
        {
            return true;
        }

        MessageBox.Show(this, string.Join(Environment.NewLine, errors), "Paramètres à corriger", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return false;
    }

    private bool Ask(string question) =>
        MessageBox.Show(this, question, "SecureDesk", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;

    private string? ChooseSave(string fileName, string title)
    {
        using var dlg = new SaveFileDialog { FileName = fileName, Title = title, Filter = "Tous les fichiers|*.*", OverwritePrompt = true };
        return dlg.ShowDialog(this) == DialogResult.OK ? dlg.FileName : null;
    }

    private string? ChooseOpen(string filter)
    {
        using var dlg = new OpenFileDialog { Filter = filter };
        return dlg.ShowDialog(this) == DialogResult.OK ? dlg.FileName : null;
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (_busy)
        {
            e.Cancel = true;
            MessageBox.Show(this, "Une opération est en cours : patientez.", "SecureDesk");
            return;
        }

        SaveAssistantConfig();
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _fileLog.Dispose();
        }

        base.Dispose(disposing);
    }
}

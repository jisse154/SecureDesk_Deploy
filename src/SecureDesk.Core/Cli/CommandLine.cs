using System.Globalization;

namespace SecureDesk.Core.Cli;

public sealed class CommandLineException(string message) : Exception(message);

/// <summary>Analyse minimale et stricte de la ligne de commande : « verbe [argument] [--option valeur] [--drapeau] ».</summary>
public sealed class CommandLine
{
    /// <summary>Options qui attendent une valeur.</summary>
    public static readonly IReadOnlySet<string> ValueOptions = new HashSet<string>(StringComparer.Ordinal)
    {
        "config", "out", "name", "peer", "scope", "export", "sha256", "wireguard-msi", "multiotp-msi", "vcredist",
        "tsplus-setup", "endpoint", "port", "subnet", "users", "lan-subnet",
    };

    /// <summary>Options sans valeur.</summary>
    public static readonly IReadOnlySet<string> FlagOptions = new HashSet<string>(StringComparer.Ordinal)
    {
        "dry-run", "yes", "verbose", "server", "i-have-console-access", "from-probation", "remove-accounts",
        "allow-lan", "auto-start", "manual-start", "tsplus-silent", "help",
    };

    public static readonly IReadOnlyList<(string Verb, string Role, string Help)> Verbs =
    [
        ("precheck", "S/C", "Pré-vérifications (lecture seule)"),
        ("init", "S", "Installe WireGuard, crée le tunnel et le pare-feu, exporte l'invitation chiffrée"),
        ("invite", "S", "Crée une invitation pour un nouveau pair (--name)"),
        ("add-peer", "S", "Ajoute le pair décrit par un fichier pairing-client.sdpair"),
        ("list-peers", "S", "Liste les pairs et invitations"),
        ("revoke-peer", "S", "Révoque un pair (nom)"),
        ("rotate-keys", "S", "Rotation : --server (clés du serveur) ou --peer <nom> (PSK du pair)"),
        ("tsplus-check", "S", "Détecte TSplus, guide l'installation, arrête le serveur web TSplus"),
        ("accounts", "S", "Crée/vérifie les comptes, groupe RDP, stratégie de mots de passe"),
        ("harden", "S", "Durcissement RDP, audit, journaux, heure Windows, contrôle BitLocker"),
        ("install-2fa", "S", "Installe multiOTP Credential Provider (DÉSACTIVÉ)"),
        ("enroll-user", "S", "Enrôle un compte Windows dans multiOTP (QR code, vérification, codes de secours)"),
        ("enable-2fa", "S", "Active le 2FA en mode probatoire (--scope remote|all)"),
        ("confirm-2fa", "S", "Confirme l'activation du 2FA (annule la désactivation automatique)"),
        ("disable-2fa", "S", "Désactive le 2FA (à la console)"),
        ("join", "C", "Appaire ce PC client à partir de pairing-server.sdpair"),
        ("rdp-shortcut", "C", "Crée le raccourci .rdp sur le bureau"),
        ("test", "C", "Teste le tunnel et l'accès RDP"),
        ("diagnose", "S/C", "État complet sans secret (--export fichier)"),
        ("report", "S", "Rapport final et checklist de la box"),
        ("uninstall", "S/C", "Rollback complet (--remove-accounts pour supprimer les comptes créés)"),
        ("wizard", "S/C", "Ouvre l'assistant graphique"),
        ("version", "S/C", "Affiche la version"),
    ];

    public string Verb { get; private init; } = "wizard";
    public string? Argument { get; private init; }
    public IReadOnlyDictionary<string, string> Values { get; private init; } = new Dictionary<string, string>();
    public IReadOnlySet<string> Flags { get; private init; } = new HashSet<string>();

    public bool Has(string flag) => Flags.Contains(flag);

    public string? Get(string option) => Values.TryGetValue(option, out var v) ? v : null;

    public int? GetInt(string option)
    {
        var v = Get(option);
        if (v is null)
        {
            return null;
        }

        return int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var i) ? i : throw new CommandLineException($"--{option} : nombre attendu.");
    }

    public bool DryRun => Has("dry-run");

    public static CommandLine Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count == 0)
        {
            return new CommandLine();
        }

        string? verb = null;
        string? argument = null;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                var name = a[2..];
                string? inline = null;
                var eq = name.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0)
                {
                    inline = name[(eq + 1)..];
                    name = name[..eq];
                }

                if (ValueOptions.Contains(name))
                {
                    var value = inline ?? (i + 1 < args.Count ? args[++i] : throw new CommandLineException($"--{name} attend une valeur."));
                    if (!values.TryAdd(name, value))
                    {
                        throw new CommandLineException($"--{name} est indiqué deux fois.");
                    }
                }
                else if (FlagOptions.Contains(name) && inline is null)
                {
                    flags.Add(name);
                }
                else
                {
                    throw new CommandLineException($"Option inconnue : {a}");
                }
            }
            else if (a is "-h" or "/?")
            {
                flags.Add("help");
            }
            else if (verb is null)
            {
                verb = a.ToLowerInvariant();
                if (Verbs.All(v => v.Verb != verb))
                {
                    throw new CommandLineException($"Commande inconnue : {a}. Tapez « SecureDesk.exe --help ».");
                }
            }
            else if (argument is null)
            {
                argument = a;
            }
            else
            {
                throw new CommandLineException($"Argument en trop : {a}");
            }
        }

        return new CommandLine { Verb = verb ?? (flags.Contains("help") ? "help" : "wizard"), Argument = argument, Values = values, Flags = flags };
    }

    public static string Usage()
    {
        var lines = new List<string>
        {
            "SecureDesk — bureau à distance sécurisé (WireGuard + TSplus + multiOTP)",
            string.Empty,
            "Usage : SecureDesk.exe [commande] [argument] [options]",
            "        (sans commande : assistant graphique)",
            string.Empty,
            "Commandes (S = serveur, C = client) :",
        };
        lines.AddRange(Verbs.Select(v => $"  {v.Verb,-14} [{v.Role,-3}] {v.Help}"));
        lines.AddRange(
        [
            string.Empty,
            "Options générales :",
            "  --config <fichier.json>   paramètres (aucun secret dans ce fichier)",
            "  --dry-run                 liste les actions sans rien modifier",
            "  --yes                     répond « oui » aux confirmations",
            "  --verbose                 affiche le détail du journal",
            "  --out <chemin>            fichier/dossier de sortie (fichiers d'appairage)",
            "  --sha256 <empreinte>      empreinte SHA-256 d'un installeur fourni hors ligne",
            "  --wireguard-msi | --multiotp-msi | --vcredist | --tsplus-setup <chemin>   installeurs locaux (hors ligne)",
            "Options serveur : --endpoint <ip|ddns> --port <udp> --subnet <cidr> --users a,b --allow-lan [--lan-subnet <cidr>] --name <pair> --tsplus-silent",
            "Options 2FA     : --scope remote|all  --i-have-console-access",
            "Options client  : --auto-start | --manual-start",
            string.Empty,
            "Journaux : %ProgramData%\\SecureDesk\\logs (aucun secret n'y est écrit).",
        ]);
        return string.Join(Environment.NewLine, lines);
    }
}

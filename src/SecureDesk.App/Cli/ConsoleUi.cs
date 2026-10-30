using System.Text;
using QRCoder;
using SecureDesk.Core.Security;
using SecureDesk.Windows.Ops;

namespace SecureDesk.App.Cli;

/// <summary>Interface console. Les secrets sont saisis sans écho ; QR et codes sont effacés de l'écran après lecture.</summary>
internal sealed class ConsoleUi(bool assumeYes) : IUi
{
    public void Info(string message) => Console.WriteLine(message);

    public void Warn(string message) => Write(ConsoleColor.Yellow, "ATTENTION : " + message);

    public void Error(string message) => Write(ConsoleColor.Red, "ERREUR : " + message);

    public void Show(string title, IReadOnlyList<string> lines)
    {
        Console.WriteLine();
        Write(ConsoleColor.Cyan, "── " + title + " ──");
        foreach (var l in lines)
        {
            Console.WriteLine("  " + l);
        }

        Console.WriteLine();
    }

    public bool Confirm(string question, bool defaultAnswer = false)
    {
        if (assumeYes)
        {
            Console.WriteLine(question + " → oui (--yes)");
            return true;
        }

        while (true)
        {
            Console.Write($"{question} [{(defaultAnswer ? "O/n" : "o/N")}] ");
            var r = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(r))
            {
                return defaultAnswer;
            }

            if (r is "o" or "oui" or "y" or "yes")
            {
                return true;
            }

            if (r is "n" or "non" or "no")
            {
                return false;
            }
        }
    }

    public string Ask(string question, string? defaultValue = null)
    {
        Console.Write(defaultValue is null ? $"{question} : " : $"{question} [{defaultValue}] : ");
        var r = Console.ReadLine();
        return string.IsNullOrWhiteSpace(r) ? defaultValue ?? string.Empty : r.Trim();
    }

    public SensitiveText AskSecret(string prompt, bool confirm)
    {
        while (true)
        {
            var first = ReadHidden(prompt + " : ");
            if (!confirm)
            {
                return first;
            }

            var second = ReadHidden("Confirmez : ");
            if (first.Equals(second))
            {
                return first;
            }

            Warn("Les deux saisies diffèrent.");
        }
    }

    public void ShowQrOnce(string title, string provisioningText)
    {
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(provisioningText, QRCodeGenerator.ECCLevel.M);
        var m = data.ModuleMatrix;
        var sb = new StringBuilder();
        // Deux lignes de modules par ligne de texte (demi-blocs), fond blanc forcé pour la lisibilité.
        for (var y = 0; y < m.Count; y += 2)
        {
            for (var x = 0; x < m.Count; x++)
            {
                var top = m[y][x];
                var bottom = y + 1 < m.Count && m[y + 1][x];
                sb.Append((top, bottom) switch
                {
                    (true, true) => ' ',
                    (true, false) => '▄',
                    (false, true) => '▀',
                    _ => '█',
                });
            }

            sb.Append('\n');
        }

        Console.WriteLine();
        Write(ConsoleColor.Cyan, title);
        var previous = Console.OutputEncoding;
        Console.OutputEncoding = Encoding.UTF8;
        var fg = Console.ForegroundColor;
        var bg = Console.BackgroundColor;
        Console.ForegroundColor = ConsoleColor.White;
        Console.BackgroundColor = ConsoleColor.Black;
        Console.Write(sb.ToString());
        Console.ForegroundColor = fg;
        Console.BackgroundColor = bg;
        Console.OutputEncoding = previous;
        Console.WriteLine("Appuyez sur Entrée une fois le QR code scanné (il sera effacé de l'écran).");
        Console.ReadLine();
        ClearScreen();
    }

    public void ShowSecretsOnce(string title, IReadOnlyList<string> lines)
    {
        Show(title, lines);
        Console.WriteLine("Appuyez sur Entrée après les avoir notés (ils seront effacés de l'écran).");
        Console.ReadLine();
        ClearScreen();
    }

    private static void ClearScreen()
    {
        try
        {
            Console.Clear();
            // Efface aussi l'historique de défilement (terminaux compatibles VT).
            Console.Write("\u001b[3J");
        }
        catch (IOException)
        {
        }
    }

    private static SensitiveText ReadHidden(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected)
        {
            return new SensitiveText(Console.ReadLine() ?? string.Empty);
        }

        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
            }
        }

        var result = new SensitiveText(sb.ToString());
        sb.Clear();
        return result;
    }

    private static void Write(ConsoleColor color, string message)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = old;
    }
}

using QRCoder;
using SecureDesk.Core.Security;
using SecureDesk.Windows.Ops;

namespace SecureDesk.App.Gui;

/// <summary>IUi pour l'assistant : les opérations tournent en arrière-plan, les dialogues sont ramenés sur le thread UI.</summary>
internal sealed class GuiUi(Form owner, Action<string, Color> appendLog) : IUi
{
    private T OnUi<T>(Func<T> f) => owner.InvokeRequired ? (T)owner.Invoke(f) : f();

    private void OnUi(Action a)
    {
        if (owner.InvokeRequired)
        {
            owner.Invoke(a);
        }
        else
        {
            a();
        }
    }

    public void Info(string message) => OnUi(() => appendLog(message, SystemColors.WindowText));

    public void Warn(string message) => OnUi(() => appendLog("ATTENTION : " + message, Color.DarkOrange));

    public void Error(string message) => OnUi(() => appendLog("ERREUR : " + message, Color.Firebrick));

    public void Show(string title, IReadOnlyList<string> lines) => OnUi(() =>
    {
        appendLog("── " + title + " ──", Color.SteelBlue);
        foreach (var l in lines)
        {
            appendLog("  " + l, SystemColors.WindowText);
        }

        using var dlg = new TextDialog(title, string.Join(Environment.NewLine, lines), secret: false);
        dlg.ShowDialog(owner);
    });

    public bool Confirm(string question, bool defaultAnswer = false) => OnUi(() =>
        MessageBox.Show(owner, question, "SecureDesk", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
            defaultAnswer ? MessageBoxDefaultButton.Button1 : MessageBoxDefaultButton.Button2) == DialogResult.Yes);

    public string Ask(string question, string? defaultValue = null) => OnUi(() =>
    {
        using var dlg = new InputDialog(question, defaultValue ?? string.Empty, password: false);
        return dlg.ShowDialog(owner) == DialogResult.OK ? dlg.Value : defaultValue ?? string.Empty;
    });

    public SensitiveText AskSecret(string prompt, bool confirm) => OnUi(() =>
    {
        while (true)
        {
            using var dlg = new InputDialog(prompt, string.Empty, password: true);
            if (dlg.ShowDialog(owner) != DialogResult.OK)
            {
                throw new OperationException("Saisie annulée.");
            }

            var first = new SensitiveText(dlg.Value);
            if (!confirm)
            {
                return first;
            }

            using var dlg2 = new InputDialog("Confirmez : " + prompt, string.Empty, password: true);
            if (dlg2.ShowDialog(owner) != DialogResult.OK)
            {
                throw new OperationException("Saisie annulée.");
            }

            if (first.Equals(new SensitiveText(dlg2.Value)))
            {
                return first;
            }

            MessageBox.Show(owner, "Les deux saisies diffèrent.", "SecureDesk", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    });

    public void ShowQrOnce(string title, string provisioningText) => OnUi(() =>
    {
        using var dlg = new QrDialog(title, provisioningText);
        dlg.ShowDialog(owner);
    });

    public void ShowSecretsOnce(string title, IReadOnlyList<string> lines) => OnUi(() =>
    {
        using var dlg = new TextDialog(title, string.Join(Environment.NewLine, lines), secret: true);
        dlg.ShowDialog(owner);
    });
}

internal sealed class InputDialog : Form
{
    private readonly TextBox _box;

    public InputDialog(string prompt, string value, bool password)
    {
        Text = "SecureDesk";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(12);
        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Fill };
        layout.Controls.Add(new Label { Text = prompt, AutoSize = true, MaximumSize = new Size(480, 0) });
        _box = new TextBox { Text = value, Width = 460, UseSystemPasswordChar = password };
        layout.Controls.Add(_box);
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true };
        var cancel = new Button { Text = "Annuler", DialogResult = DialogResult.Cancel, AutoSize = true };
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        buttons.Controls.AddRange([cancel, ok]);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    public string Value => _box.Text;

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);
        _box.Clear();
    }
}

/// <summary>Texte à lire (instructions, ou secrets affichés une seule fois : pas de copie, effacé à la fermeture).</summary>
internal sealed class TextDialog : Form
{
    private readonly TextBox _text;

    public TextDialog(string title, string body, bool secret)
    {
        Text = title;
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(760, 460);
        MinimizeBox = false;
        _text = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            Text = body,
            Font = new Font(FontFamily.GenericMonospace, secret ? 13 : 10),
            ShortcutsEnabled = !secret,
        };
        var ok = new Button { Text = secret ? "J'ai noté — effacer" : "OK", Dock = DockStyle.Bottom, Height = 36, DialogResult = DialogResult.OK };
        Controls.Add(_text);
        Controls.Add(ok);
        AcceptButton = ok;
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);
        _text.Clear();
    }
}

/// <summary>QR code rendu en mémoire (aucun fichier), affiché une seule fois puis libéré.</summary>
internal sealed class QrDialog : Form
{
    private readonly PictureBox _picture;

    public QrDialog(string title, string provisioningText)
    {
        Text = "Enrôlement 2FA";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = MaximizeBox = false;
        ClientSize = new Size(460, 560);
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(provisioningText, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(8);
        using var ms = new MemoryStream(png);
        using var decoded = Image.FromStream(ms);
        _picture = new PictureBox { Image = new Bitmap(decoded), SizeMode = PictureBoxSizeMode.Zoom, Dock = DockStyle.Fill };
        Array.Clear(png);
        var label = new Label { Text = title, Dock = DockStyle.Top, Height = 60, TextAlign = ContentAlignment.MiddleCenter };
        var ok = new Button { Text = "J'ai scanné le QR code", Dock = DockStyle.Bottom, Height = 40, DialogResult = DialogResult.OK };
        Controls.Add(_picture);
        Controls.Add(label);
        Controls.Add(ok);
        AcceptButton = ok;
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);
        var img = _picture.Image;
        _picture.Image = null;
        img?.Dispose();
    }
}

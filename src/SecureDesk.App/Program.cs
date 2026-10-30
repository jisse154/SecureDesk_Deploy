using System.Runtime.InteropServices;
using SecureDesk.App.Cli;
using SecureDesk.App.Gui;
using SecureDesk.Core.Cli;

namespace SecureDesk.App;

internal static partial class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        CommandLine cl;
        try
        {
            cl = CommandLine.Parse(args);
        }
        catch (CommandLineException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 64;
        }

        if (cl.Verb == "wizard")
        {
            HideOwnConsole();
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
            return 0;
        }

        return Commands.Run(cl);
    }

    /// <summary>Lancé par double-clic, l'exécutable console ouvre sa propre fenêtre : on la masque pour l'assistant.</summary>
    private static void HideOwnConsole()
    {
        var processes = new uint[2];
        if (GetConsoleProcessList(processes, 2) == 1)
        {
            ShowWindow(GetConsoleWindow(), 0);
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial uint GetConsoleProcessList([Out] uint[] processList, uint count);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetConsoleWindow();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShowWindow(IntPtr hWnd, int nCmdShow);
}

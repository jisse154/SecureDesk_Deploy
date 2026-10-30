using System.Globalization;
using Microsoft.Win32;
using SecureDesk.Core.Hardening;
using SecureDesk.Core.State;

namespace SecureDesk.Windows.Sys;

/// <summary>Accès HKLM (vue 64 bits) avec mémorisation de la valeur d'origine pour le rollback.</summary>
public static class RegistryOps
{
    public const string RollbackKind = "registry";
    private const string Absent = "\u0000absent";

    public static RegistryKey Hklm() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    public static object? Read(string path, string name)
    {
        using var hklm = Hklm();
        using var key = hklm.OpenSubKey(path);
        return key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    }

    public static string? ReadString(string path, string name) => Read(path, name)?.ToString();

    public static int? ReadDword(string path, string name) => Read(path, name) is int i ? i : null;

    public static bool Matches(RegistryValueSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        var current = Read(spec.Path, spec.Name);
        return spec.Kind switch
        {
            RegKind.DWord => current is int i && i == Convert.ToInt32(spec.Value, CultureInfo.InvariantCulture),
            _ => current is string s && s == (string)spec.Value,
        };
    }

    /// <summary>Écrit la valeur après avoir mémorisé l'origine (une seule fois).</summary>
    public static void Set(RegistryValueSpec spec, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(state);
        RecordOriginal(spec.Path, spec.Name, state);
        using var hklm = Hklm();
        using var key = hklm.CreateSubKey(spec.Path, writable: true);
        if (spec.Kind == RegKind.DWord)
        {
            key.SetValue(spec.Name, Convert.ToInt32(spec.Value, CultureInfo.InvariantCulture), RegistryValueKind.DWord);
        }
        else
        {
            key.SetValue(spec.Name, (string)spec.Value, RegistryValueKind.String);
        }
    }

    public static void RecordOriginal(string path, string name, SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var current = Read(path, name);
        string kind;
        string? value;
        switch (current)
        {
            case null:
                kind = "absent";
                value = Absent;
                break;
            case int i:
                kind = "dword";
                value = i.ToString(CultureInfo.InvariantCulture);
                break;
            default:
                kind = "string";
                value = current.ToString();
                break;
        }

        state.RecordOriginal($"reg:{path}\\{name}", RollbackKind, new Dictionary<string, string?>
        {
            ["path"] = path,
            ["name"] = name,
            ["kind"] = kind,
            ["value"] = value,
        });
    }

    /// <summary>Restaure une valeur mémorisée (supprime la valeur si elle n'existait pas).</summary>
    public static void Restore(RollbackRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var path = record.Data["path"]!;
        var name = record.Data["name"]!;
        using var hklm = Hklm();
        switch (record.Data["kind"])
        {
            case "absent":
                using (var key = hklm.OpenSubKey(path, writable: true))
                {
                    key?.DeleteValue(name, throwOnMissingValue: false);
                }

                // Clé de stratégie devenue vide : on la retire aussi (retour à l'état initial).
                using (var check = hklm.OpenSubKey(path))
                {
                    if (check is { ValueCount: 0, SubKeyCount: 0 } && path.StartsWith(@"SOFTWARE\Policies\", StringComparison.OrdinalIgnoreCase))
                    {
                        check.Close();
                        hklm.DeleteSubKey(path, throwOnMissingSubKey: false);
                    }
                }

                break;
            case "dword":
                using (var key = hklm.CreateSubKey(path, writable: true))
                {
                    key.SetValue(name, int.Parse(record.Data["value"]!, CultureInfo.InvariantCulture), RegistryValueKind.DWord);
                }

                break;
            default:
                using (var key = hklm.CreateSubKey(path, writable: true))
                {
                    key.SetValue(name, record.Data["value"] ?? string.Empty, RegistryValueKind.String);
                }

                break;
        }
    }
}

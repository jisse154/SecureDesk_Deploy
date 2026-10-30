using System.Globalization;
using System.Text;

namespace SecureDesk.Core.Logging;

public enum LogLevel
{
    Debug,
    Info,
    Warning,
    Error,
}

public interface ILog
{
    void Write(LogLevel level, string message);
}

public static class LogExtensions
{
    public static void Debug(this ILog log, string message) => log?.Write(LogLevel.Debug, message);
    public static void Info(this ILog log, string message) => log?.Write(LogLevel.Info, message);
    public static void Warn(this ILog log, string message) => log?.Write(LogLevel.Warning, message);
    public static void Error(this ILog log, string message) => log?.Write(LogLevel.Error, message);
}

/// <summary>Journal fichier. Tout passe par <see cref="Redactor"/> avant écriture.</summary>
public sealed class FileLog : ILog, IDisposable
{
    private readonly StreamWriter _writer;
    private readonly Lock _gate = new();

    public FileLog(string directory, TimeProvider? clock = null)
    {
        Directory.CreateDirectory(directory);
        var now = (clock ?? TimeProvider.System).GetLocalNow();
        Path = System.IO.Path.Combine(directory, string.Create(CultureInfo.InvariantCulture, $"securedesk-{now:yyyyMMdd}.log"));
        _writer = new StreamWriter(new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.Read), new UTF8Encoding(false)) { AutoFlush = true };
        Clock = clock ?? TimeProvider.System;
    }

    public string Path { get; }
    private TimeProvider Clock { get; }

    public void Write(LogLevel level, string message)
    {
        var line = string.Create(CultureInfo.InvariantCulture, $"{Clock.GetLocalNow():yyyy-MM-dd HH:mm:ss.fff} [{level}] {Redactor.Redact(message)}");
        lock (_gate)
        {
            _writer.WriteLine(line);
        }
    }

    public void Dispose() => _writer.Dispose();
}

/// <summary>Diffuse vers plusieurs journaux.</summary>
public sealed class CompositeLog(params ILog[] targets) : ILog
{
    public void Write(LogLevel level, string message)
    {
        foreach (var t in targets)
        {
            t.Write(level, message);
        }
    }
}

/// <summary>Journal en mémoire (tests, rapport d'assistant).</summary>
public sealed class MemoryLog : ILog
{
    private readonly List<(LogLevel Level, string Message)> _entries = [];
    private readonly Lock _gate = new();

    public IReadOnlyList<(LogLevel Level, string Message)> Entries
    {
        get
        {
            lock (_gate)
            {
                return [.. _entries];
            }
        }
    }

    public void Write(LogLevel level, string message)
    {
        lock (_gate)
        {
            _entries.Add((level, Redactor.Redact(message)));
        }
    }

    public string AllText() => string.Join('\n', Entries.Select(e => e.Message));
}

public sealed class NullLog : ILog
{
    public static readonly NullLog Instance = new();

    public void Write(LogLevel level, string message)
    {
    }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using SecureDesk.Core.Config;

namespace SecureDesk.Core.State;

/// <summary>Enregistrement de rollback : valeur d'origine d'un réglage modifié par SecureDesk. Jamais de secret.</summary>
public sealed class RollbackRecord
{
    public string Key { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public Dictionary<string, string?> Data { get; set; } = [];
    public DateTimeOffset RecordedUtc { get; set; }
}

public sealed class PeerRecord
{
    public string Name { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string TunnelIp { get; set; } = string.Empty;
    public string InvitationId { get; set; } = string.Empty;
    public DateTimeOffset AddedUtc { get; set; }
}

public sealed class InvitationRecord
{
    public string Id { get; set; } = string.Empty;
    public string PeerName { get; set; } = string.Empty;
    public string TunnelIp { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }
    public bool Consumed { get; set; }
}

public sealed class ServerState
{
    public string TunnelName { get; set; } = string.Empty;
    public string TunnelSubnet { get; set; } = string.Empty;
    public int ListenPort { get; set; }
    public string EndpointHost { get; set; } = string.Empty;
    public int RdpPort { get; set; } = 3389;
    public string ServerPublicKey { get; set; } = string.Empty;
    public List<PeerRecord> Peers { get; set; } = [];
    public List<InvitationRecord> Invitations { get; set; } = [];
}

public sealed class ClientState
{
    public string TunnelName { get; set; } = string.Empty;
    public string ServerTunnelIp { get; set; } = string.Empty;
    public int RdpPort { get; set; } = 3389;
    public string ClientPublicKey { get; set; } = string.Empty;
    public string ServerPublicKey { get; set; } = string.Empty;
    public string InvitationId { get; set; } = string.Empty;
    public string PeerName { get; set; } = string.Empty;
    public bool AutoStart { get; set; }
    public string? RdpShortcutPath { get; set; }
}

public sealed class EnrolledUser
{
    public string Name { get; set; } = string.Empty;
    public bool IsAdministrator { get; set; }
    public DateTimeOffset VerifiedUtc { get; set; }
}

public sealed class TwoFactorState
{
    public bool Installed { get; set; }
    public bool Active { get; set; }
    public TwoFactorScope Scope { get; set; } = TwoFactorScope.RemoteOnly;
    public List<EnrolledUser> Users { get; set; } = [];
    public DateTimeOffset? ProbationDeadlineUtc { get; set; }
    public bool Confirmed { get; set; }
}

public sealed class SecureDeskState
{
    public int SchemaVersion { get; set; } = 1;
    public string? Role { get; set; }
    public ServerState? Server { get; set; }
    public ClientState? Client { get; set; }
    public TwoFactorState TwoFactor { get; set; } = new();
    public List<RollbackRecord> Rollback { get; set; } = [];

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static SecureDeskState FromJson(string json) =>
        JsonSerializer.Deserialize<SecureDeskState>(json, JsonOptions) ?? new SecureDeskState();

    /// <summary>Enregistre la valeur d'origine seulement la première fois (idempotence : on ne l'écrase jamais).</summary>
    public bool RecordOriginal(string key, string kind, IDictionary<string, string?> data, TimeProvider? clock = null)
    {
        if (Rollback.Any(r => r.Key == key))
        {
            return false;
        }

        Rollback.Add(new RollbackRecord
        {
            Key = key,
            Kind = kind,
            Data = new Dictionary<string, string?>(data),
            RecordedUtc = (clock ?? TimeProvider.System).GetUtcNow(),
        });
        return true;
    }
}

public interface IStateStore
{
    SecureDeskState Load();
    void Save(SecureDeskState state);
}

public sealed class FileStateStore(string path) : IStateStore
{
    public string Path { get; } = path;

    public SecureDeskState Load() => File.Exists(Path) ? SecureDeskState.FromJson(File.ReadAllText(Path)) : new SecureDeskState();

    public void Save(SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var dir = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        // Écriture atomique : fichier temporaire puis remplacement.
        var tmp = Path + ".tmp";
        File.WriteAllText(tmp, state.ToJson());
        File.Move(tmp, Path, overwrite: true);
    }
}

public sealed class MemoryStateStore : IStateStore
{
    private string _json = new SecureDeskState().ToJson();

    public SecureDeskState Load() => SecureDeskState.FromJson(_json);

    public void Save(SecureDeskState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        _json = state.ToJson();
    }

    public string RawJson => _json;
}

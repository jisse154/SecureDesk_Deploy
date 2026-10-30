using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureDesk.Core.Security;

namespace SecureDesk.Core.Pairing;

/// <summary>Contenu (déchiffré) du fichier d'appairage serveur : une invitation pour un pair.</summary>
public sealed record ServerInvitation
{
    public required string InvitationId { get; init; }
    public required string PeerName { get; init; }
    public required WgPublicKey ServerPublicKey { get; init; }
    public required string EndpointHost { get; init; }
    public required int EndpointPort { get; init; }
    public required string ServerTunnelIp { get; init; }
    public required string ClientTunnelIp { get; init; }
    public required string TunnelSubnet { get; init; }
    public required int RdpPort { get; init; }
    public required WgSecretKey PresharedKey { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required DateTimeOffset ExpiresUtc { get; init; }

    public override string ToString() => $"Invitation {InvitationId} pour « {PeerName} » (serveur {ServerPublicKey.Fingerprint})";
}

/// <summary>Contenu du fichier d'appairage client : clé publique uniquement, authentifiée par la PSK.</summary>
public sealed record ClientResponse
{
    public required string InvitationId { get; init; }
    public required string PeerName { get; init; }
    public required WgPublicKey ClientPublicKey { get; init; }
    public required string ClientTunnelIp { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
}

public sealed class PairingException(string message) : Exception(message);

/// <summary>
/// Format .sdpair (JSON, UTF-8).
/// Serveur : AES-256-GCM, clé = PBKDF2-HMAC-SHA256(phrase de passe, sel 16 o, 600 000 itérations), en-tête authentifié (AAD).
/// Client : en clair, MAC HMAC-SHA256 avec une clé dérivée de la PSK (HKDF-SHA256).
/// Aucune clé privée n'y figure jamais.
/// </summary>
public static class PairingFile
{
    public const string Format = "securedesk-pairing";
    public const int Version = 1;
    public const int DefaultIterations = 600_000;
    public const int MinIterations = 100_000;
    public const string ServerFileName = "pairing-server.sdpair";
    public const string ClientFileName = "pairing-client.sdpair";
    private static readonly byte[] ClientMacInfo = Encoding.ASCII.GetBytes("securedesk-client-mac-v1");

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed class Envelope
    {
        public string Format { get; set; } = string.Empty;
        public int Version { get; set; }
        public string Kind { get; set; } = string.Empty;
        public KdfInfo? Kdf { get; set; }
        public string? Nonce { get; set; }
        public string? Tag { get; set; }
        public string? Ciphertext { get; set; }
        public ClientPayload? Payload { get; set; }
        public string? Mac { get; set; }
    }

    private sealed class KdfInfo
    {
        public string Name { get; set; } = string.Empty;
        public int Iterations { get; set; }
        public string Salt { get; set; } = string.Empty;
    }

    private sealed class ServerPayload
    {
        public string InvitationId { get; set; } = string.Empty;
        public string PeerName { get; set; } = string.Empty;
        public string ServerPublicKey { get; set; } = string.Empty;
        public string EndpointHost { get; set; } = string.Empty;
        public int EndpointPort { get; set; }
        public string ServerTunnelIp { get; set; } = string.Empty;
        public string ClientTunnelIp { get; set; } = string.Empty;
        public string TunnelSubnet { get; set; } = string.Empty;
        public int RdpPort { get; set; }
        public string PresharedKey { get; set; } = string.Empty;
        public DateTimeOffset CreatedUtc { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
    }

    private sealed class ClientPayload
    {
        public string InvitationId { get; set; } = string.Empty;
        public string PeerName { get; set; } = string.Empty;
        public string ClientPublicKey { get; set; } = string.Empty;
        public string ClientTunnelIp { get; set; } = string.Empty;
        public DateTimeOffset CreatedUtc { get; set; }
    }

    // ---------- Serveur ----------

    public static string WriteServer(ServerInvitation invitation, SensitiveText passphrase, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentNullException.ThrowIfNull(passphrase);
        var problems = PassphrasePolicy.Check(passphrase);
        if (problems.Count > 0)
        {
            throw new PairingException(string.Join(" ", problems));
        }

        var payload = new ServerPayload
        {
            InvitationId = invitation.InvitationId,
            PeerName = invitation.PeerName,
            ServerPublicKey = invitation.ServerPublicKey.Value,
            EndpointHost = invitation.EndpointHost,
            EndpointPort = invitation.EndpointPort,
            ServerTunnelIp = invitation.ServerTunnelIp,
            ClientTunnelIp = invitation.ClientTunnelIp,
            TunnelSubnet = invitation.TunnelSubnet,
            RdpPort = invitation.RdpPort,
            PresharedKey = invitation.PresharedKey.Reveal(),
            CreatedUtc = invitation.CreatedUtc,
            ExpiresUtc = invitation.ExpiresUtc,
        };
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload, Json);
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[plaintext.Length];
        var key = DeriveKey(passphrase, salt, iterations);
        try
        {
            var kdf = new KdfInfo { Name = "PBKDF2-SHA256", Iterations = iterations, Salt = Convert.ToBase64String(salt) };
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Aad("server", kdf));
            var env = new Envelope
            {
                Format = Format,
                Version = Version,
                Kind = "server",
                Kdf = kdf,
                Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag),
                Ciphertext = Convert.ToBase64String(ciphertext),
            };
            return JsonSerializer.Serialize(env, Json);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static ServerInvitation ReadServer(string json, SensitiveText passphrase, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        var env = ParseEnvelope(json, "server");
        if (env.Kdf is null || env.Kdf.Name != "PBKDF2-SHA256" || env.Kdf.Iterations < MinIterations || env.Nonce is null || env.Tag is null || env.Ciphertext is null)
        {
            throw new PairingException("Fichier d'appairage serveur incomplet ou paramètres de chiffrement non acceptés.");
        }

        byte[] salt, nonce, tag, ciphertext;
        try
        {
            salt = Convert.FromBase64String(env.Kdf.Salt);
            nonce = Convert.FromBase64String(env.Nonce);
            tag = Convert.FromBase64String(env.Tag);
            ciphertext = Convert.FromBase64String(env.Ciphertext);
        }
        catch (FormatException)
        {
            throw new PairingException("Fichier d'appairage serveur corrompu (base64).");
        }

        if (salt.Length < 16 || nonce.Length != 12 || tag.Length != 16)
        {
            throw new PairingException("Fichier d'appairage serveur corrompu (tailles).");
        }

        var plaintext = new byte[ciphertext.Length];
        var key = DeriveKey(passphrase, salt, env.Kdf.Iterations);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Aad("server", env.Kdf));
            var p = JsonSerializer.Deserialize<ServerPayload>(plaintext, Json) ?? throw new PairingException("Contenu vide.");
            var inv = new ServerInvitation
            {
                InvitationId = p.InvitationId,
                PeerName = p.PeerName,
                ServerPublicKey = new WgPublicKey(p.ServerPublicKey),
                EndpointHost = p.EndpointHost,
                EndpointPort = p.EndpointPort,
                ServerTunnelIp = p.ServerTunnelIp,
                ClientTunnelIp = p.ClientTunnelIp,
                TunnelSubnet = p.TunnelSubnet,
                RdpPort = p.RdpPort,
                PresharedKey = new WgSecretKey(p.PresharedKey),
                CreatedUtc = p.CreatedUtc,
                ExpiresUtc = p.ExpiresUtc,
            };
            if ((clock ?? TimeProvider.System).GetUtcNow() > inv.ExpiresUtc)
            {
                throw new PairingException(string.Create(CultureInfo.InvariantCulture,
                    $"Cette invitation a expiré le {inv.ExpiresUtc:yyyy-MM-dd HH:mm} UTC. Générez-en une nouvelle sur le serveur (SecureDesk.exe invite)."));
            }

            return inv;
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new PairingException("Phrase de passe incorrecte ou fichier modifié.");
        }
        catch (FormatException ex)
        {
            throw new PairingException("Contenu du fichier d'appairage invalide : " + ex.Message);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    // ---------- Client ----------

    public static string WriteClient(ClientResponse response, WgSecretKey presharedKey)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(presharedKey);
        var payload = new ClientPayload
        {
            InvitationId = response.InvitationId,
            PeerName = response.PeerName,
            ClientPublicKey = response.ClientPublicKey.Value,
            ClientTunnelIp = response.ClientTunnelIp,
            CreatedUtc = response.CreatedUtc,
        };
        var env = new Envelope
        {
            Format = Format,
            Version = Version,
            Kind = "client",
            Payload = payload,
            Mac = Convert.ToBase64String(ClientMac(payload, presharedKey)),
        };
        return JsonSerializer.Serialize(env, Json);
    }

    /// <summary>Lit l'identifiant d'invitation sans vérifier le MAC (pour retrouver la PSK correspondante).</summary>
    public static string PeekClientInvitationId(string json) =>
        ParseEnvelope(json, "client").Payload?.InvitationId ?? throw new PairingException("Fichier client sans identifiant d'invitation.");

    public static ClientResponse ReadClient(string json, WgSecretKey presharedKey)
    {
        ArgumentNullException.ThrowIfNull(presharedKey);
        var env = ParseEnvelope(json, "client");
        if (env.Payload is null || env.Mac is null)
        {
            throw new PairingException("Fichier d'appairage client incomplet.");
        }

        byte[] mac;
        try
        {
            mac = Convert.FromBase64String(env.Mac);
        }
        catch (FormatException)
        {
            throw new PairingException("MAC du fichier client corrompu.");
        }

        if (!CryptographicOperations.FixedTimeEquals(mac, ClientMac(env.Payload, presharedKey)))
        {
            throw new PairingException("Authentification du fichier client refusée : il ne correspond pas à cette invitation ou a été modifié.");
        }

        try
        {
            return new ClientResponse
            {
                InvitationId = env.Payload.InvitationId,
                PeerName = env.Payload.PeerName,
                ClientPublicKey = new WgPublicKey(env.Payload.ClientPublicKey),
                ClientTunnelIp = env.Payload.ClientTunnelIp,
                CreatedUtc = env.Payload.CreatedUtc,
            };
        }
        catch (FormatException ex)
        {
            throw new PairingException("Contenu du fichier client invalide : " + ex.Message);
        }
    }

    // ---------- Interne ----------

    private static Envelope ParseEnvelope(string json, string expectedKind)
    {
        Envelope? env;
        try
        {
            env = JsonSerializer.Deserialize<Envelope>(json, Json);
        }
        catch (JsonException)
        {
            throw new PairingException("Ce fichier n'est pas un fichier d'appairage SecureDesk.");
        }

        if (env is null || env.Format != Format)
        {
            throw new PairingException("Ce fichier n'est pas un fichier d'appairage SecureDesk.");
        }

        if (env.Version != Version)
        {
            throw new PairingException(string.Create(CultureInfo.InvariantCulture, $"Version de fichier d'appairage non prise en charge : {env.Version}."));
        }

        if (env.Kind != expectedKind)
        {
            throw new PairingException(expectedKind == "server"
                ? "Ce fichier est un fichier d'appairage CLIENT : il s'importe sur le serveur (add-peer)."
                : "Ce fichier est un fichier d'appairage SERVEUR : il s'importe sur le client (join).");
        }

        return env;
    }

    private static byte[] Aad(string kind, KdfInfo kdf) =>
        Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture, $"{Format}|{Version}|{kind}|{kdf.Name}|{kdf.Iterations}|{kdf.Salt}"));

    private static byte[] DeriveKey(SensitiveText passphrase, byte[] salt, int iterations)
    {
        var pass = passphrase.RevealUtf8();
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(pass, salt, iterations, HashAlgorithmName.SHA256, 32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pass);
        }
    }

    private static byte[] ClientMac(ClientPayload p, WgSecretKey psk)
    {
        var ikm = Convert.FromBase64String(psk.Reveal());
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt: null, info: ClientMacInfo);
        try
        {
            var canonical = string.Join('\n',
                Format,
                Version.ToString(CultureInfo.InvariantCulture),
                "client",
                p.InvitationId,
                p.PeerName,
                p.ClientPublicKey,
                p.ClientTunnelIp,
                p.CreatedUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(canonical));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ikm);
        }
    }
}

public static class PassphrasePolicy
{
    public const int MinLength = 14;

    public static IReadOnlyList<string> Check(SensitiveText passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        var problems = new List<string>();
        var p = passphrase.Reveal();
        if (p.Length < MinLength)
        {
            problems.Add(string.Create(CultureInfo.InvariantCulture, $"La phrase de passe doit contenir au moins {MinLength} caractères."));
        }

        if (p.Distinct().Count() < 6)
        {
            problems.Add("La phrase de passe est trop répétitive.");
        }

        return problems;
    }

    private const string Alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // sans 0/O, 1/I/L, U : lisible et dictable

    /// <summary>Génère une phrase de passe de 6 groupes de 4 caractères (≈ 118 bits).</summary>
    public static SensitiveText Generate()
    {
        var groups = new string[6];
        for (var g = 0; g < groups.Length; g++)
        {
            var chars = new char[4];
            for (var i = 0; i < 4; i++)
            {
                chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
            }

            groups[g] = new string(chars);
        }

        return new SensitiveText(string.Join('-', groups));
    }
}

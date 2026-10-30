using System.Security.Cryptography;
using System.Text;
using SecureDesk.Core.Security;

namespace SecureDesk.Windows.Sys;

/// <summary>
/// Stockage des PSK d'invitations en attente (le serveur la génère avant de connaître le client) :
/// DPAPI portée machine + fichier à ACL SYSTEM/Administrateurs. Supprimée dès que le pair est ajouté (elle est alors dans le .conf).
/// </summary>
public static class SecretStore
{
    private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("SecureDesk-invitation-psk-v1");

    private static string PathFor(string invitationId)
    {
        if (invitationId.Any(c => !char.IsAsciiLetterOrDigit(c)))
        {
            throw new ArgumentException("Identifiant d'invitation invalide.", nameof(invitationId));
        }

        return Path.Combine(SecureFiles.SecretsDir, "inv-" + invitationId + ".bin");
    }

    public static void Save(string invitationId, WgSecretKey psk)
    {
        ArgumentNullException.ThrowIfNull(psk);
        var plain = Encoding.ASCII.GetBytes(psk.Reveal());
        try
        {
            var blob = ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);
            SecureFiles.EnsureProtectedDirectory(SecureFiles.SecretsDir);
            var path = PathFor(invitationId);
            SecureFiles.WriteProtected(path, Convert.ToBase64String(blob));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static WgSecretKey? Load(string invitationId)
    {
        var path = PathFor(invitationId);
        if (!File.Exists(path))
        {
            return null;
        }

        var plain = ProtectedData.Unprotect(Convert.FromBase64String(File.ReadAllText(path)), Entropy, DataProtectionScope.LocalMachine);
        try
        {
            return new WgSecretKey(Encoding.ASCII.GetString(plain));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static void Delete(string invitationId) => SecureFiles.BestEffortWipe(PathFor(invitationId));
}

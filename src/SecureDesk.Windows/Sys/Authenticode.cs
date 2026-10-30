using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureDesk.Windows.Sys;

public sealed record SignatureInfo(bool Valid, int Status, string? Subject)
{
    public override string ToString() => Valid ? $"signature valide ({Subject})" : $"signature INVALIDE ou absente (0x{Status:X8})";
}

/// <summary>Vérification Authenticode via WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2).</summary>
public static partial class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint CbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string FilePath;
        public IntPtr HFile;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

#pragma warning disable SYSLIB1054, CA5392 // DllImport classique : structure non blittable (chaîne marshalée), wintrust.dll est un DLL système.
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WinTrustData data);
#pragma warning restore SYSLIB1054, CA5392

    public static SignatureInfo Verify(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            CbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = Path.GetFullPath(path),
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WinTrustData
            {
                CbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = WtdUiNone,
                // Pas de vérification de révocation en ligne : l'outil doit fonctionner hors ligne.
                // L'intégrité est en plus garantie par l'empreinte SHA-256 épinglée quand elle est connue.
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                FileInfo = pFile,
                StateAction = WtdStateActionVerify,
                ProvFlags = WtdCacheOnlyUrlRetrieval,
            };
            var action = GenericVerifyV2;
            var status = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.StateAction = WtdStateActionClose;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return new SignatureInfo(status == 0, status, status == 0 ? SignerSubject(path) : null);
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static string? SignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>Signature valide ET éditeur attendu (si précisé).</summary>
    public static bool IsTrusted(string path, string? expectedSubjectContains, out SignatureInfo info)
    {
        info = Verify(path);
        return info.Valid && (string.IsNullOrEmpty(expectedSubjectContains) ||
            (info.Subject?.Contains(expectedSubjectContains, StringComparison.OrdinalIgnoreCase) ?? false));
    }
}

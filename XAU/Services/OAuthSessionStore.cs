using System.Security.Cryptography;
using System.Text;
using System.IO;
using Newtonsoft.Json;
using XboxAuthNet.OAuth;

namespace XAU.Services;

public interface IOAuthSessionProtection
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] ciphertext);
}

public sealed class CurrentUserOAuthSessionProtection : IOAuthSessionProtection
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("XAU-Auth-v1");
    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
    public byte[] Unprotect(byte[] ciphertext) =>
        ProtectedData.Unprotect(ciphertext, Entropy, DataProtectionScope.CurrentUser);
}

public sealed class OAuthSessionPersistenceException : IOException
{
    [Newtonsoft.Json.JsonIgnore]
    [System.Text.Json.Serialization.JsonIgnore]
    public string? ProtectedRecoveryPath { get; }
    public bool RecoveryRetained => ProtectedRecoveryPath != null;

    public OAuthSessionPersistenceException(string? protectedRecoveryPath, Exception inner)
        : base("The refreshed OAuth session could not be saved.", inner)
        => ProtectedRecoveryPath = protectedRecoveryPath;
}

/// <summary>The XAU session file only; no Windows broker/cache or account-store enumeration.</summary>
public sealed class OAuthSessionStore
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("XAU1");
    private readonly string _path;
    private readonly IOAuthSessionProtection _protection;

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "XAU", "auth.json");

    public OAuthSessionStore(string path, IOAuthSessionProtection protection)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A session path is required.", nameof(path));
        _path = Path.GetFullPath(path);
        _protection = protection ?? throw new ArgumentNullException(nameof(protection));
    }

    // Callers hold this OS file lease across read -> refresh -> persist. It
    // works across awaits/processes; a crashed process releases its handle.
    public async Task<IDisposable> AcquireLeaseAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(_path + ".lock", FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (attempt < 40)
            {
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public MicrosoftOAuthResponse Read()
    {
        var raw = File.ReadAllBytes(_path);
        byte[]? plain = null;
        try
        {
            // Preserve compatibility with both the XAU1 DPAPI format and
            // historical plaintext sessions written by older XAU versions.
            plain = raw.AsSpan().StartsWith(Magic)
                ? _protection.Unprotect(raw.AsSpan(Magic.Length).ToArray())
                : raw;
            return JsonConvert.DeserializeObject<MicrosoftOAuthResponse>(Encoding.UTF8.GetString(plain))
                ?? throw new InvalidDataException("The saved OAuth session was empty.");
        }
        finally
        {
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    public void Write(MicrosoftOAuthResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var directory = Path.GetDirectoryName(_path)!;
        var temporary = Path.Combine(directory, ".auth-" + Guid.NewGuid().ToString("N") + ".tmp");
        byte[]? plain = null;
        byte[]? encrypted = null;
        var protectedFileComplete = false;
        var installed = false;
        try
        {
            Directory.CreateDirectory(directory);
            plain = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(response));
            encrypted = _protection.Protect(plain);
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(Magic);
                file.Write(encrypted);
                file.Flush(flushToDisk: true);
            }
            protectedFileComplete = true;
            // A failed write/protection step leaves the previous session intact.
            // Replace also retains the existing Windows destination ACL.
            if (File.Exists(_path)) File.Replace(temporary, _path, null);
            else File.Move(temporary, _path);
            installed = true;
        }
        catch (Exception ex)
        {
            // Preserve the newly rotated credential as a complete encrypted
            // XAU1 envelope if installation fails. It remains readable using
            // this same store/protector with ProtectedRecoveryPath explicitly.
            throw new OAuthSessionPersistenceException(protectedFileComplete ? temporary : null, ex);
        }
        finally
        {
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
            if (encrypted != null) CryptographicOperations.ZeroMemory(encrypted);
            if ((!protectedFileComplete || installed) && File.Exists(temporary))
            {
                // Cleanup failure must not turn a classified persistence error
                // into a refresh failure and trigger another OAuth request.
                try { File.Delete(temporary); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
}

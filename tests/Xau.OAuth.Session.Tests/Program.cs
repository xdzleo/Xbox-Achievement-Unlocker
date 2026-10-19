using System.IO;
using System.Text;
using Newtonsoft.Json;
using XboxAuthNet.OAuth;
using XAU.Services;

internal static class Program
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-18T18:00:00Z");
    private static int _passed;

    private static MicrosoftOAuthResponse Saved(bool valid = false, string? refresh = "M.R3_BAY.SYNTHETIC-before") => new()
    {
        AccessToken = "SYNTHETIC-access", RawRefreshToken = refresh,
        ExpiresOn = valid ? Now.AddHours(1) : Now.AddHours(-1)
    };

    private static void Assert(bool value) { if (!value) throw new Exception("Synthetic session test failed."); }
    private static async Task Run(string name, Func<Task> test)
    {
        await test(); _passed++; Console.WriteLine("PASS " + name);
    }

    public static async Task Main()
    {
        await Run("expired access token can refresh", async () =>
        {
            var calls = 0;
            var result = await OAuthSessionRenewal.RestoreAsync(Saved(), (token, _) =>
            { calls++; Assert(token == "SYNTHETIC-before"); return Task.FromResult(Saved(true)); }, utcNow: () => Now);
            Assert(calls == 1 && result.ExpiresOn > Now);
        });
        await Run("missing access token does not discard refresh", async () =>
        {
            var saved = Saved(); saved.AccessToken = null;
            var result = await OAuthSessionRenewal.RestoreAsync(saved, (_, _) => Task.FromResult(Saved(true)), utcNow: () => Now);
            Assert(result.ExpiresOn > Now);
        });
        await Run("omitted refresh token preserves original raw representation", async () =>
        {
            var saved = Saved();
            var result = await OAuthSessionRenewal.RestoreAsync(saved, (_, _) => Task.FromResult(Saved(true, null)), utcNow: () => Now);
            Assert(result.RawRefreshToken == saved.RawRefreshToken);
        });
        await Run("rotation replaces refresh token without mutating old session", async () =>
        {
            var saved = Saved();
            var result = await OAuthSessionRenewal.RestoreAsync(saved,
                (_, _) => Task.FromResult(Saved(true, "M.R3_BAY.SYNTHETIC-after")), utcNow: () => Now);
            Assert(result.RawRefreshToken == "M.R3_BAY.SYNTHETIC-after" && saved.RawRefreshToken == "M.R3_BAY.SYNTHETIC-before");
        });
        await Run("cancellation before refresh makes no request", async () =>
        {
            using var cts = new CancellationTokenSource(); cts.Cancel(); var calls = 0;
            try
            {
                await OAuthSessionRenewal.RestoreAsync(Saved(), (_, _) => { calls++; return Task.FromResult(Saved(true)); }, cts.Token, () => Now);
                Assert(false);
            }
            catch (OperationCanceledException) { Assert(calls == 0); }
        });
        await Run("cancellation after successful rotation still returns credential for persistence", async () =>
        {
            using var cts = new CancellationTokenSource();
            var result = await OAuthSessionRenewal.RestoreAsync(Saved(), (_, _) =>
            { cts.Cancel(); return Task.FromResult(Saved(true, "M.R3_BAY.SYNTHETIC-after")); }, cts.Token, () => Now);
            Assert(cts.IsCancellationRequested && result.RawRefreshToken == "M.R3_BAY.SYNTHETIC-after");
        });
        await Run("valid access token without refresh is usable without network", async () =>
        {
            var saved = Saved(true, null); var calls = 0;
            var result = await OAuthSessionRenewal.RestoreAsync(saved, (_, _) => { calls++; return Task.FromResult(Saved(true)); }, utcNow: () => Now);
            Assert(ReferenceEquals(saved, result) && calls == 0);
        });
        await Run("expired session without refresh requires interactive login", async () =>
        {
            var calls = 0;
            try
            {
                await OAuthSessionRenewal.RestoreAsync(Saved(false, null), (_, _) => { calls++; return Task.FromResult(Saved(true)); }, utcNow: () => Now);
                Assert(false);
            }
            catch (InvalidOperationException) { Assert(calls == 0); }
        });
        await Run("invalid refresh success is not accepted", async () =>
        {
            try
            {
                await OAuthSessionRenewal.RestoreAsync(Saved(), (_, _) => Task.FromResult(Saved(false, null)), utcNow: () => Now);
                Assert(false);
            }
            catch (InvalidOperationException) { }
        });

        var testBase = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "session-fixtures"));
        var directory = Path.GetFullPath(Path.Combine(testBase, Guid.NewGuid().ToString("N")));
        Assert(directory.StartsWith(testBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "auth.json");
            var store = new OAuthSessionStore(path, new FakeProtection());
            await Run("XAU1 and Newtonsoft session roundtrip", () =>
            {
                store.Write(Saved(true));
                var raw = File.ReadAllBytes(path);
                Assert(raw.AsSpan(0, 4).SequenceEqual(Encoding.ASCII.GetBytes("XAU1")));
                Assert(!Encoding.UTF8.GetString(raw).Contains("SYNTHETIC-access", StringComparison.Ordinal));
                var read = store.Read();
                Assert(read.AccessToken == "SYNTHETIC-access" && read.RawRefreshToken == "M.R3_BAY.SYNTHETIC-before");
                return Task.CompletedTask;
            });
            await Run("legacy plaintext Newtonsoft sessions still read", () =>
            {
                File.WriteAllText(path, JsonConvert.SerializeObject(Saved(true)));
                Assert(store.Read().RawRefreshToken == "M.R3_BAY.SYNTHETIC-before");
                store.Write(Saved(true)); return Task.CompletedTask;
            });
            await Run("protection failure preserves previous file", () =>
            {
                var before = File.ReadAllBytes(path);
                try { new OAuthSessionStore(path, new FailingProtection()).Write(Saved(true)); Assert(false); }
                catch (OAuthSessionPersistenceException ex)
                { Assert(!ex.RecoveryRetained && before.SequenceEqual(File.ReadAllBytes(path))); }
                return Task.CompletedTask;
            });
            await Run("failed replace retains protected recoverable rotated credential", () =>
            {
                var before = File.ReadAllBytes(path);
                using var denyReplace = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                try { store.Write(Saved(true, "M.R3_BAY.SYNTHETIC-after")); Assert(false); }
                catch (OAuthSessionPersistenceException ex)
                {
                    Assert(before.SequenceEqual(File.ReadAllBytes(path)));
                    Assert(ex.RecoveryRetained);
                    var recovery = new OAuthSessionStore(ex.ProtectedRecoveryPath!, new FakeProtection()).Read();
                    Assert(recovery.RawRefreshToken == "M.R3_BAY.SYNTHETIC-after");
                    Assert(!JsonConvert.SerializeObject(ex).Contains(ex.ProtectedRecoveryPath!, StringComparison.Ordinal));
                }
                return Task.CompletedTask;
            });
            await Run("OS lease prevents concurrent refresh and honors cancellation", async () =>
            {
                using (await store.AcquireLeaseAsync(CancellationToken.None))
                {
                    using var cts = new CancellationTokenSource(120);
                    try { using var unexpected = await store.AcquireLeaseAsync(cts.Token); Assert(false); }
                    catch (OperationCanceledException) { }
                }
                using var available = await store.AcquireLeaseAsync(CancellationToken.None);
            });
        }
        finally
        {
            // Resolve and check this generated, exclusively owned fixture path
            // before recursively deleting it; never use the actual XAU store.
            var resolved = Path.GetFullPath(directory);
            Assert(resolved.StartsWith(testBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
            Directory.Delete(resolved, recursive: true);
        }
        Console.WriteLine($"PASS {_passed} synthetic OAuth session tests; no auth or service requests.");
    }

    private sealed class FakeProtection : IOAuthSessionProtection
    {
        // Test-only transform, not an encryption implementation.
        public byte[] Protect(byte[] bytes) => bytes.Select(b => (byte)(b ^ 0xA5)).ToArray();
        public byte[] Unprotect(byte[] bytes) => Protect(bytes);
    }
    private sealed class FailingProtection : IOAuthSessionProtection
    {
        public byte[] Protect(byte[] bytes) => throw new InvalidOperationException("Synthetic failure.");
        public byte[] Unprotect(byte[] bytes) => throw new InvalidOperationException("Synthetic failure.");
    }
}

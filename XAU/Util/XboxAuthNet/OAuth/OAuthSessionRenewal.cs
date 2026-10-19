using System;
using System.Threading;
using System.Threading.Tasks;

namespace XboxAuthNet.OAuth;

/// <summary>Restores an app-owned session without treating access-token expiry as refresh-token expiry.</summary>
public static class OAuthSessionRenewal
{
    public static async Task<MicrosoftOAuthResponse> RestoreAsync(
        MicrosoftOAuthResponse saved,
        Func<string, CancellationToken, Task<MicrosoftOAuthResponse>> refresh,
        CancellationToken cancellationToken = default,
        Func<DateTimeOffset>? utcNow = null)
    {
        if (saved == null) throw new ArgumentNullException(nameof(saved));
        if (refresh == null) throw new ArgumentNullException(nameof(refresh));
        cancellationToken.ThrowIfCancellationRequested();
        utcNow ??= () => DateTimeOffset.UtcNow;

        // RefreshToken uses the existing XAU representation. An expired or
        // missing access token does not invalidate this separate credential.
        var refreshToken = saved.RefreshToken;
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            if (IsUsable(saved, utcNow())) return saved;
            throw new InvalidOperationException("The saved OAuth session requires interactive login.");
        }

        var renewed = await refresh(refreshToken!, cancellationToken).ConfigureAwait(false);
        // A successful response can rotate the refresh credential even when
        // cancellation was requested concurrently. Return it for persistence
        // before the caller cancels subsequent Xbox work.
        if (renewed == null || !IsUsable(renewed, utcNow()))
            throw new InvalidOperationException("OAuth refresh did not return a usable session.");

        // Providers may omit an unchanged refresh token. Preserve the original
        // raw representation; keep any actual replacement returned by OAuth.
        if (string.IsNullOrWhiteSpace(renewed.RawRefreshToken))
            renewed.RawRefreshToken = saved.RawRefreshToken;
        return renewed;
    }

    private static bool IsUsable(MicrosoftOAuthResponse response, DateTimeOffset now) =>
        !string.IsNullOrWhiteSpace(response.AccessToken) && response.ExpiresOn > now;
}

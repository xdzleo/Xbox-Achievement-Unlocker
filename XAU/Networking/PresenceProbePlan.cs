// Deterministic request matrix for comparing presence behavior across tokens.
//
// Nothing here assumes why one token works and another does not. The tokens
// are encrypted (JWE), so their claims cannot be read client-side; the only
// observable is the service response. To attribute a difference to the token
// rather than to the request, every token is probed with exactly the same
// steps, headers and bodies. Only Authorization (and, when the token is bound
// to a ProofKey XAU holds, Signature) vary.
public static class PresenceProbePlan
{
    public sealed record Step(string Name, string Method, string Url, string? Body, bool Signed, bool IsReadback);

    public static IReadOnlyList<Step> Build(string? xuid, string? titleId, bool hasSigner)
    {
        if (string.IsNullOrEmpty(xuid) || xuid.Any(c => c < '0' || c > '9'))
            return Array.Empty<Step>();
        if (!PresenceVerification.TryCanonicalTitleId(titleId, out var id))
            return Array.Empty<Step>();

        var heartbeatUrl = string.Format(InterpolatedXboxAPIUrls.HeartbeatUrl, xuid);
        var currentTitleUrl = string.Format(InterpolatedXboxAPIUrls.PresenceUrl, xuid);
        var readUrl = string.Format(InterpolatedXboxAPIUrls.PresenceReadUrl, xuid);

        // (name, method, url, body). Bodies use the exact property order of
        // the upstream HeartbeatRequest/TitleRequest and the native writer.
        var writes = new (string Name, string Url, string Body)[]
        {
            ("heartbeat-string-id", heartbeatUrl, $"{{\"titles\":[{{\"expiration\":600,\"id\":\"{id}\",\"state\":\"active\",\"sandbox\":\"RETAIL\"}}]}}"),
            ("heartbeat-numeric-id", heartbeatUrl, $"{{\"titles\":[{{\"expiration\":600,\"id\":{id},\"state\":\"active\",\"sandbox\":\"RETAIL\"}}]}}"),
            ("current-title-state-only", currentTitleUrl, "{\"state\":\"active\"}"),
            ("current-title-id-placement", currentTitleUrl, $"{{\"id\":\"{id}\",\"state\":\"active\",\"placement\":\"full\"}}"),
        };

        var steps = new List<Step>
        {
            new("readback-before/unsigned", "GET", readUrl, null, false, true)
        };
        foreach (var signed in hasSigner ? new[] { false, true } : new[] { false })
        {
            var mode = signed ? "signed" : "unsigned";
            foreach (var write in writes)
            {
                steps.Add(new Step($"{write.Name}/{mode}", "POST", write.Url, write.Body, signed, false));
                steps.Add(new Step($"readback-after-{write.Name}/{mode}", "GET", readUrl, null, signed, true));
            }
        }
        return steps;
    }
}

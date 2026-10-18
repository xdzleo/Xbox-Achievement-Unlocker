using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace XboxAuthNet.XboxLive.Responses;

/// <summary>
/// Per-operation context recovered from SISU response headers. It is not an
/// XSTS token or a presence permission. Do not persist or log these values.
/// </summary>
public sealed class XboxSisuContext
{
    [JsonIgnore]
    public string? SessionId { get; }

    [JsonIgnore]
    public string? ClusterAffinity { get; }

    private XboxSisuContext(string? sessionId, string? clusterAffinity) =>
        (SessionId, ClusterAffinity) = (sessionId, clusterAffinity);

    public static XboxSisuContext FromHeaders(HttpResponseHeaders headers) =>
        new(ReadSingle(headers, "X-SessionId"), ReadSingle(headers, "X-Cluster-Affinity"));

    private static string? ReadSingle(HttpResponseHeaders headers, string name)
    {
        if (!headers.TryGetValues(name, out var values))
            return null;
        var entries = values.ToArray();
        // These are local transport bounds, not a claim about the native
        // parser's behavior for ambiguous or malformed headers.
        if (entries.Length != 1 || entries[0].Length > 4096 || entries[0].Any(char.IsControl))
            throw new JsonException($"Invalid SISU {name} header");
        return entries[0].Length == 0 ? null : entries[0];
    }
}

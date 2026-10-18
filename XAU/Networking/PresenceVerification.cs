using System.Text.Json;

// Pure presence decisions shared by XboxRestAPI and the offline tests.
//
// The native current-title writer (xgameruntime FUN_180257230) sends only
// {"state":"active"}. That body carries no title id, so the service can only
// bind the write to the title identity inside the presenting XToken. A 200
// response therefore proves the write was accepted for the token's title, not
// for the title XAU was asked to show.
public static class PresenceVerification
{
    public enum StateOnlyBinding
    {
        // Token title claim equals the requested title.
        Bound,
        // Token title claim is known and differs: the write would target
        // another title (for OAuth, the Xbox App client title).
        Mismatch,
        // No title claim is known for this token (e.g. a token read from
        // process memory). Only a read-back can decide.
        Unknown
    }

    public static StateOnlyBinding ClassifyStateOnlyWrite(string? tokenTitleId, string requestedTitleId)
    {
        if (!TryCanonicalTitleId(requestedTitleId, out var requested))
            return StateOnlyBinding.Mismatch;
        if (string.IsNullOrWhiteSpace(tokenTitleId))
            return StateOnlyBinding.Unknown;
        return TryCanonicalTitleId(tokenTitleId, out var token) && token == requested
            ? StateOnlyBinding.Bound
            : StateOnlyBinding.Mismatch;
    }

    public sealed record ReadbackResult(bool Parsed, bool RequestedTitleActive, int TitleCount, IReadOnlyList<string> ActiveTitleIds);

    // Parses a userpresence GET /users/xuid({xuid})?level=all body and reports
    // whether the requested title is listed as active on any device. Only
    // numeric title ids are returned so callers can log them without
    // echoing arbitrary service text.
    public static ReadbackResult ParseReadback(string? json, string requestedTitleId)
    {
        var empty = new ReadbackResult(false, false, 0, Array.Empty<string>());
        if (string.IsNullOrWhiteSpace(json) || !TryCanonicalTitleId(requestedTitleId, out var requested))
            return empty;

        JsonDocument document;
        try { document = JsonDocument.Parse(json); }
        catch (JsonException) { return empty; }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return empty;

            var count = 0;
            var active = new List<string>();
            var found = false;
            if (TryGetPropertyIgnoreCase(root, "devices", out var devices) && devices.ValueKind == JsonValueKind.Array)
            {
                foreach (var device in devices.EnumerateArray())
                {
                    if (device.ValueKind != JsonValueKind.Object
                        || !TryGetPropertyIgnoreCase(device, "titles", out var titles)
                        || titles.ValueKind != JsonValueKind.Array)
                        continue;

                    foreach (var title in titles.EnumerateArray())
                    {
                        if (title.ValueKind != JsonValueKind.Object)
                            continue;
                        count++;
                        if (!TryGetPropertyIgnoreCase(title, "id", out var idElement))
                            continue;
                        var idText = idElement.ValueKind switch
                        {
                            JsonValueKind.String => idElement.GetString(),
                            JsonValueKind.Number => idElement.GetRawText(),
                            _ => null
                        };
                        if (!TryCanonicalTitleId(idText, out var id))
                            continue;

                        var isActive = !TryGetPropertyIgnoreCase(title, "state", out var state)
                            || state.ValueKind != JsonValueKind.String
                            || string.Equals(state.GetString(), "active", StringComparison.OrdinalIgnoreCase);
                        if (!isActive)
                            continue;
                        active.Add(id.ToString());
                        if (id == requested)
                            found = true;
                    }
                }
            }

            return new ReadbackResult(true, found, count, active);
        }
    }

    public static bool TryCanonicalTitleId(string? value, out ulong titleId)
    {
        titleId = 0;
        if (string.IsNullOrWhiteSpace(value) || value.Any(c => c < '0' || c > '9'))
            return false;
        return ulong.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out titleId)
            && titleId != 0;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }
        value = default;
        return false;
    }
}

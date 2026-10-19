using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.Requests;
using XboxAuthNet.XboxLive.Responses;

namespace XboxAuthNet.XboxLive.DeviceRps;

public sealed class DeviceRpsResponseMetadata
{
    public int StatusCode { get; internal set; }
    public int ResponseBytes { get; internal set; }
    public bool ResponseTooLarge { get; internal set; }
    public bool JsonObject { get; internal set; }
    public bool XErrFormatValid { get; internal set; }
    public uint? XErr { get; internal set; }
    public bool TokenPresent { get; internal set; }
    public bool IssueInstantValid { get; internal set; }
    public bool NotAfterValid { get; internal set; }
    public bool TimeWindowValid { get; internal set; }
    public bool Accepted => StatusCode >= 200 && StatusCode <= 299 && !ResponseTooLarge
        && JsonObject && XErrFormatValid && (XErr == null || XErr == 0)
        && TokenPresent && IssueInstantValid && NotAfterValid && TimeWindowValid;
}

/// <summary>Only the device exchange is established. This does not establish user/title/presence binding.</summary>
public sealed class DeviceRpsTokenResult
{
    internal DeviceRpsTokenResult(XboxAuthResponse token, DeviceRpsAcquisitionMetadata acquisition,
        DeviceRpsResponseMetadata response)
        => (Token, Acquisition, Response) = (token, acquisition, response);

    [JsonIgnore, System.Runtime.Serialization.IgnoreDataMember]
    public XboxAuthResponse Token { get; }
    public DeviceRpsAcquisitionMetadata Acquisition { get; }
    public DeviceRpsResponseMetadata Response { get; }
    public override string ToString() => "DeviceRpsTokenResult (credential redacted)";
}

/// <summary>Safe failure metadata; no raw service message, body, ticket, token or inner exception.</summary>
public sealed class DeviceRpsException : Exception
{
    internal DeviceRpsException(string failureKind, DeviceRpsAcquisitionMetadata? acquisition = null,
        DeviceRpsResponseMetadata? response = null, int? causeHResult = null)
        : base("Device RPS failed: " + failureKind)
        => (FailureKind, Acquisition, Response, CauseHResult) = (failureKind, acquisition, response, causeHResult);

    public string FailureKind { get; }
    public DeviceRpsAcquisitionMetadata? Acquisition { get; }
    public DeviceRpsResponseMetadata? Response { get; }
    public int? CauseHResult { get; }
}

/// <summary>Explicit, replaceable device-ticket acquisition and signed RPS exchange, with no fallback.</summary>
public sealed class DeviceRpsTokenProvider
{
    public const string Endpoint = "https://device.auth.xboxlive.com/device/authenticate";
    public const int MaxResponseBytes = 65536;
    private readonly IDeviceRpsTicketProvider _tickets;
    private readonly Func<DateTimeOffset> _utcNow;

    public DeviceRpsTokenProvider(IDeviceRpsTicketProvider tickets, Func<DateTimeOffset>? utcNow = null)
    {
        _tickets = tickets ?? throw new ArgumentNullException(nameof(tickets));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Owned transport for real exchanges. Injected clients must also prohibit redirects.</summary>
    public static HttpClient CreateHttpClient() => new HttpClient(new HttpClientHandler
    {
        AllowAutoRedirect = false, UseCookies = false, Credentials = null,
        PreAuthenticate = false, UseProxy = false
    });

    public async Task<DeviceRpsTokenResult> AcquireAsync(DeviceRpsTicketRequest request,
        HttpClient httpClient, IXboxRequestSigner signer, CancellationToken cancellationToken = default,
        string? deviceVersion = null)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
        if (signer == null) throw new ArgumentNullException(nameof(signer));
        cancellationToken.ThrowIfCancellationRequested();

        object proofKey;
        try
        {
            // Snapshot the public JWK once; this same signer signs the serialized body below.
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(signer.ProofKey));
            ValidatePublicProofKey(document.RootElement);
            proofKey = document.RootElement.Clone();
        }
        catch (Exception error) when (IsOperationalFailure(error))
        {
            throw new DeviceRpsException("invalid_proof_key", causeHResult: error.HResult);
        }

        DeviceRpsTicket ticket;
        try { ticket = await _tickets.AcquireAsync(request, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { throw new OperationCanceledException(cancellationToken); }
        catch (Exception error) when (IsOperationalFailure(error))
        { throw new DeviceRpsException("acquisition_exception", causeHResult: error.HResult); }

        var acquisition = ticket?.Metadata;
        if (ticket == null || acquisition == null || !acquisition.Accepted
            || string.IsNullOrEmpty(ticket.Value) || ticket.Value!.Length != acquisition.TicketUtf16Length)
            throw new DeviceRpsException("acquisition_rejected", acquisition);
        cancellationToken.ThrowIfCancellationRequested();

        string body;
        string signature;
        try
        {
            var wire = new RpsWireRequest
            {
                AuthenticationMethod = XboxDeviceAuthenticationMethod.DeviceRps,
                RpsTicket = ticket.Value, DeviceVersion = deviceVersion
            };
            body = wire.Serialize(proofKey);
            signature = signer.SignRequest(Endpoint, "", body);
            var header = Convert.FromBase64String(signature);
            if (header.Length != 76 || header[0] != 0 || header[1] != 0 || header[2] != 0 || header[3] != 1)
                throw new InvalidOperationException();
        }
        catch (Exception error) when (IsOperationalFailure(error))
        { throw new DeviceRpsException("request_signing_failed", acquisition, causeHResult: error.HResult); }

        using var message = new HttpRequestMessage(HttpMethod.Post, Endpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        message.Headers.Add("Signature", signature);
        message.Headers.Add("x-xbl-contract-version", "1");
        CommonRequestHeaders.AddDefaultHeaders(message);

        DeviceRpsResponseMetadata? responseMetadata = null;
        try
        {
            using var response = await httpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            responseMetadata = new DeviceRpsResponseMetadata { StatusCode = (int)response.StatusCode };
            var bytes = await ReadBoundedAsync(response, responseMetadata, cancellationToken).ConfigureAwait(false);
            if (responseMetadata.ResponseTooLarge)
                throw new DeviceRpsException("response_too_large", acquisition, responseMetadata);

            XboxAuthResponse? token = null;
            try { token = ParseResponse(bytes, responseMetadata, _utcNow()); }
            catch (JsonException) { /* Safe metadata distinguishes parse failure from HTTP rejection. */ }
            if (!responseMetadata.Accepted || token == null)
                throw new DeviceRpsException(response.IsSuccessStatusCode ? "invalid_response" : "http_error",
                    acquisition, responseMetadata);
            return new DeviceRpsTokenResult(token, acquisition, responseMetadata);
        }
        catch (DeviceRpsException) { throw; }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { throw new OperationCanceledException(cancellationToken); }
        catch (Exception error) when (IsOperationalFailure(error))
        { throw new DeviceRpsException("transport_error", acquisition, responseMetadata, error.HResult); }
    }

    private static bool IsOperationalFailure(Exception error) => !(error is OutOfMemoryException)
        && !(error is StackOverflowException) && !(error is AccessViolationException);

    private static void ValidatePublicProofKey(JsonElement key)
    {
        if (key.ValueKind != JsonValueKind.Object) throw new FormatException();
        var count = 0;
        foreach (var field in key.EnumerateObject())
        {
            count++;
            if (field.Name != "crv" && field.Name != "alg" && field.Name != "use"
                && field.Name != "kty" && field.Name != "x" && field.Name != "y") throw new FormatException();
        }
        if (count != 6 || key.GetProperty("crv").GetString() != "P-256"
            || key.GetProperty("alg").GetString() != "ES256" || key.GetProperty("use").GetString() != "sig"
            || key.GetProperty("kty").GetString() != "EC") throw new FormatException();
        foreach (var name in new[] { "x", "y" })
        {
            var coordinate = key.GetProperty(name).GetString();
            if (coordinate == null || coordinate.Length != 43) throw new FormatException();
            foreach (var character in coordinate)
                if (!(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z')
                    && !(character >= '0' && character <= '9') && character != '-' && character != '_')
                    throw new FormatException();
            if (Convert.FromBase64String(coordinate.Replace('-', '+').Replace('_', '/') + "=").Length != 32)
                throw new FormatException();
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response,
        DeviceRpsResponseMetadata metadata, CancellationToken cancellationToken)
    {
        if (response.Content == null) return new byte[0];
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, 0,
                Math.Min(buffer.Length, MaxResponseBytes + 1 - (int)output.Length), cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            output.Write(buffer, 0, count);
            if (output.Length > MaxResponseBytes) { metadata.ResponseTooLarge = true; break; }
        }
        metadata.ResponseBytes = (int)output.Length;
        return output.ToArray();
    }

    private static XboxAuthResponse? ParseResponse(byte[] bytes, DeviceRpsResponseMetadata metadata,
        DateTimeOffset now)
    {
        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;
        metadata.JsonObject = root.ValueKind == JsonValueKind.Object;
        if (!metadata.JsonObject) return null;
        // Duplicate properties are ambiguous. Do not accept last-value-wins credentials/status.
        var names = new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!names.Add(property.Name)) return null;
        metadata.XErrFormatValid = true;
        if (root.TryGetProperty("XErr", out var xerr))
        {
            uint code = 0;
            metadata.XErrFormatValid = xerr.ValueKind == JsonValueKind.Number ? xerr.TryGetUInt32(out code)
                : xerr.ValueKind == JsonValueKind.String
                    && uint.TryParse(xerr.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out code);
            if (metadata.XErrFormatValid) metadata.XErr = code;
        }
        var value = StringProperty(root, "Token");
        var issueText = StringProperty(root, "IssueInstant");
        var expiresText = StringProperty(root, "NotAfter");
        metadata.TokenPresent = !string.IsNullOrEmpty(value);
        metadata.IssueInstantValid = ParseInstant(issueText, out var issue);
        metadata.NotAfterValid = ParseInstant(expiresText, out var expires);
        metadata.TimeWindowValid = metadata.IssueInstantValid && metadata.NotAfterValid
            && issue <= now && expires > now && expires > issue;
        return metadata.Accepted ? new XboxAuthResponse
        { Token = value, IssueInstant = issueText, ExpireOn = expiresText } : null;
    }

    private static string? StringProperty(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool ParseInstant(string? value, out DateTimeOffset instant)
    {
        instant = default;
        // Require an explicit UTC marker or offset; local machine timezone must not change acceptance.
        return value != null && value.Contains("T") && (value.EndsWith("Z", StringComparison.Ordinal)
            || (value.Length >= 6 && (value[value.Length - 6] == '+' || value[value.Length - 6] == '-')
                && value[value.Length - 3] == ':'))
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out instant);
    }

    private sealed class RpsWireRequest : XboxDeviceTokenRequest
    {
        internal string Serialize(object proofKey) => JsonSerializer.Serialize(BuildBody(proofKey),
            new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
    }
}

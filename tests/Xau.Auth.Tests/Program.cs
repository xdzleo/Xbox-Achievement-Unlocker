using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using XboxAuthNet;
using XboxAuthNet.XboxLive;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.Requests;
using XboxAuthNet.XboxLive.Responses;

internal static class Program
{
    private static int _passed;

    public static async Task<int> Main()
    {
        await Run("signed XSTS serializes and signs exact body", SignedXstsSerializesAndSignsExactBody);
        await Run("unsigned XSTS defaults to xboxlive RP and contract 1", UnsignedXstsDefaultsToXboxLiveRp);
        await Run("Xbox App presence RP keeps HTTPS candidate separate", XboxAppPresenceRpIsExplicit);
        await Run("unsigned XSTS carries device and title tokens", UnsignedXstsCarriesAllTokenInputs);
        await Run("presence title request uses string title ID and fields", PresenceTitleRequestUsesWireShape);
        await Run("native presence request uses state-only body", NativePresenceStateRequestUsesWireShape);
        await Run("SISU default OAuth profile preserves baseline body and signature", SisuOAuthDefaultPreservesBaseline);
        await Run("SISU default OAuth omits optional null fields", SisuOAuthDefaultOmitsNullFields);
        await Run("SISU native contract is version 2 and keeps optional fields", SisuNativeContractAndFields);
        await Run("SISU native title IDs are canonical UInt64 strings", SisuNativeTitleIdsAreCanonical);
        await Run("SISU native title ID is required before signing or I/O", SisuNativeRejectsInvalidTitleIds);
        await Run("SISU OAuth rejects every native-only field before signing or I/O", SisuOAuthRejectsNativeContext);
        await Run("SISU OAuth rejects copied continuation before signing or I/O", SisuOAuthRejectsCopiedContinuation);
        await Run("SISU successful modern gamertag flags support both wire spellings", SisuResponseModernGamertagFlags);
        await Run("SISU malformed success keeps parse failure metadata and redacts body", SisuMalformedSuccessMetadata);
        await Run("SISU response retains operation-local continuation", SisuResponseRetainsContinuation);
        await Run("SISU challenge retains context without becoming success", SisuChallengeRetainsContext);
        await Run("SISU errors without WebPage have no continuation", SisuErrorsWithoutWebPage);
        await Run("SISU continuation clears missing fields", SisuContinuationClearsMissingFields);
        await Run("SISU affinity rejects unrelated endpoints atomically", SisuAffinityRejectsUnrelatedEndpoints);
        await Run("SISU partial UCS context and empty session are omitted", SisuPartialContextIsOmitted);
        await Run("SISU header bounds reject malformed context", SisuContextBounds);
        await Run("shared response handler keeps concurrent contexts separate", SisuConcurrentContextsAreSeparate);
        await Run("DisplayClaims retains title and sandbox siblings", DisplayClaimsRetainsTitleAndSandbox);
        await Run("numeric XErr is preserved as hexadecimal", NumericXErrIsHexadecimal);
        await Run("header X-Err is converted to hexadecimal", HeaderXErrIsHexadecimal);
        await Run("state-only presence write is bound only to the token title", StateOnlyPresenceBindsToTokenTitle);
        await Run("presence readback confirms only the requested active title", PresenceReadbackConfirmsRequestedTitle);
        await Run("presence readback rejects malformed or foreign bodies", PresenceReadbackRejectsMalformed);
        await Run("service signature covers method, path+query, Authorization and body", ServiceSignatureCoversRequest);
        await Run("service signature truncates body at policy MaxBodyBytes", ServiceSignatureTruncatesBody);
        await Run("auth signature keeps POST and empty token layout", AuthSignatureKeepsLegacyLayout);
        Console.WriteLine($"PASS: {_passed} offline XboxAuthNet contract tests");
        return 0;
    }

    // Reproduces the 2026-10-18 15:54 log: the OAuth presence XSTS carries the
    // OAuth client's title claim, the native state-only body names no title,
    // and the POST returned 200. That 200 cannot stand for the spoof title.
    private static Task StateOnlyPresenceBindsToTokenTitle()
    {
        const string oauthClientTitle = "1111111111";
        const string requestedTitle = "2222222222";
        Assert(PresenceVerification.ClassifyStateOnlyWrite(oauthClientTitle, requestedTitle) == PresenceVerification.StateOnlyBinding.Mismatch,
            "OAuth client title must not be treated as the requested title");
        Assert(PresenceVerification.ClassifyStateOnlyWrite("02222222222", requestedTitle) == PresenceVerification.StateOnlyBinding.Bound,
            "equal UInt64 title ids bind regardless of leading zeroes");
        Assert(PresenceVerification.ClassifyStateOnlyWrite(null, requestedTitle) == PresenceVerification.StateOnlyBinding.Unknown,
            "absent token title is unknown, not bound");
        Assert(PresenceVerification.ClassifyStateOnlyWrite("", requestedTitle) == PresenceVerification.StateOnlyBinding.Unknown,
            "empty token title is unknown");
        Assert(PresenceVerification.ClassifyStateOnlyWrite("0x2222", requestedTitle) == PresenceVerification.StateOnlyBinding.Mismatch,
            "non-decimal token title is a mismatch");
        foreach (var invalid in new[] { "", "0", "abc", "-1", "18446744073709551616" })
            Assert(PresenceVerification.ClassifyStateOnlyWrite(requestedTitle, invalid) == PresenceVerification.StateOnlyBinding.Mismatch,
                $"invalid requested title {invalid} must never bind");
        return Task.CompletedTask;
    }

    private static Task PresenceReadbackConfirmsRequestedTitle()
    {
        const string body = """
            {"xuid":"2535400000000000","state":"Online","devices":[
              {"type":"WindowsOneCore","titles":[
                {"id":"1111111111","name":"Client","placement":"Background","state":"Active"},
                {"id":"2222222222","name":"Game","placement":"Full","state":"Active"}]}]}
            """;
        var found = PresenceVerification.ParseReadback(body, "2222222222");
        Assert(found.Parsed && found.RequestedTitleActive && found.TitleCount == 2, "requested active title is confirmed");
        Assert(found.ActiveTitleIds.SequenceEqual(new[] { "1111111111", "2222222222" }), "active ids are canonical numbers");

        const string clientOnly = """
            {"devices":[{"titles":[{"id":"1111111111","state":"Active"}]}]}
            """;
        var missing = PresenceVerification.ParseReadback(clientOnly, "2222222222");
        Assert(missing.Parsed && !missing.RequestedTitleActive, "200 for the client title alone is not confirmation");

        const string inactive = """
            {"devices":[{"titles":[{"id":2222222222,"state":"Inactive"}]}]}
            """;
        Assert(!PresenceVerification.ParseReadback(inactive, "2222222222").RequestedTitleActive, "inactive title is not confirmation");

        const string numeric = """
            {"Devices":[{"Titles":[{"Id":2222222222}]}]}
            """;
        Assert(PresenceVerification.ParseReadback(numeric, "2222222222").RequestedTitleActive, "numeric id without state is accepted case-insensitively");
        return Task.CompletedTask;
    }

    private static Task PresenceReadbackRejectsMalformed()
    {
        foreach (var body in new[] { null, "", "not json", "[]", "{\"devices\":{}}", "{\"devices\":[{\"titles\":[{\"id\":\"abc\"}]}]}" })
        {
            var result = PresenceVerification.ParseReadback(body, "2222222222");
            Assert(!result.RequestedTitleActive, $"body {body ?? "null"} must not confirm presence");
        }
        Assert(!PresenceVerification.ParseReadback("{\"devices\":[]}", "0").Parsed, "invalid requested title is not parsed");
        return Task.CompletedTask;
    }

    private sealed class EcdsaPop : IPopCryptoProvider
    {
        public readonly System.Security.Cryptography.ECDsa Key =
            System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        public object ProofKey => new { kty = "EC" };
        public byte[] Sign(byte[] data) => Key.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256);
    }

    // Rebuilds the XBL v1 payload from the timestamp carried in the header and
    // verifies the ES256 signature with the public key.
    private static bool VerifyXblSignature(EcdsaPop pop, string header, string method, string pathAndQuery, string authorization, string body)
    {
        var raw = Convert.FromBase64String(header);
        if (raw.Length != 12 + 64 || raw[0] != 0 || raw[1] != 0 || raw[2] != 0 || raw[3] != 1)
            return false;
        var payload = new List<byte> { 0, 0, 0, 1, 0 };
        payload.AddRange(raw.Skip(4).Take(8));
        payload.Add(0);
        payload.AddRange(Encoding.ASCII.GetBytes($"{method}\0{pathAndQuery}\0{authorization}\0{body}\0"));
        return pop.Key.VerifyData(payload.ToArray(), raw.Skip(12).ToArray(), System.Security.Cryptography.HashAlgorithmName.SHA256);
    }

    private static Task ServiceSignatureCoversRequest()
    {
        var pop = new EcdsaPop();
        var signer = new XboxRequestSigner(pop);
        const string auth = "XBL3.0 x=123;synthetic.token";
        const string body = "{\"state\":\"active\"}";
        const string url = "https://userpresence.xboxlive.com/users/xuid(2535400000000000)/devices/current/titles/current";

        var header = signer.SignServiceRequest("post", url, auth, body);
        Assert(VerifyXblSignature(pop, header, "POST", "/users/xuid(2535400000000000)/devices/current/titles/current", auth, body),
            "POST signature verifies with method upper-cased, path, Authorization and body");
        Assert(!VerifyXblSignature(pop, header, "POST", "/users/xuid(2535400000000000)/devices/current/titles/current", "XBL3.0 x=999;other", body),
            "signature is bound to the Authorization value");
        Assert(!VerifyXblSignature(pop, header, "POST", "/users/xuid(2535400000000000)/devices/current/titles/current", auth, "{\"state\":\"inactive\"}"),
            "signature is bound to the body");

        var read = signer.SignServiceRequest("GET", "https://userpresence.xboxlive.com/users/xuid(1)?level=all", auth, "");
        Assert(VerifyXblSignature(pop, read, "GET", "/users/xuid(1)?level=all", auth, ""), "GET signature includes the query string");
        Assert(!VerifyXblSignature(pop, read, "POST", "/users/xuid(1)?level=all", auth, ""), "signature is bound to the method");

        var timestamp = BitConverter.ToUInt64(Convert.FromBase64String(read).Skip(4).Take(8).Reverse().ToArray());
        var unix = (long)(timestamp / 10_000_000UL) - 11644473600L;
        Assert(Math.Abs(unix - DateTimeOffset.UtcNow.ToUnixTimeSeconds()) < 300, "header carries a current Windows FILETIME timestamp");
        return Task.CompletedTask;
    }

    private static Task ServiceSignatureTruncatesBody()
    {
        var pop = new EcdsaPop();
        var signer = new XboxRequestSigner(pop);
        Assert(XboxRequestSigner.DefaultServiceMaxBodyBytes == 8192, "default matches NSAL SignaturePolicies[0].MaxBodyBytes");
        var header = signer.SignServiceRequest("POST", "https://presence-heartbeat.xboxlive.com/users/xuid(1)/devices/current/", "XBL3.0 x=1;t", "abcdefgh", maxBodyBytes: 4);
        Assert(VerifyXblSignature(pop, header, "POST", "/users/xuid(1)/devices/current/", "XBL3.0 x=1;t", "abcd"), "only the first MaxBodyBytes are signed");
        return Task.CompletedTask;
    }

    private static Task AuthSignatureKeepsLegacyLayout()
    {
        var pop = new EcdsaPop();
        var signer = new XboxRequestSigner(pop);
        var header = signer.SignRequest("https://xsts.auth.xboxlive.com/xsts/authorize", "", "{}");
        Assert(VerifyXblSignature(pop, header, "POST", "/xsts/authorize", "", "{}"), "auth requests still sign POST with an empty token");
        return Task.CompletedTask;
    }

    private static async Task Run(string name, Func<Task> test)
    {
        try
        {
            await test();
            _passed++;
            Console.WriteLine($"PASS {name}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL {name}: {ex.Message}");
            throw;
        }
    }

    private static async Task SignedXstsSerializesAndSignsExactBody()
    {
        var handler = new CaptureHandler(Json("Token", "signed-result"));
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256", key = "synthetic-proof-key" });
        var request = new XboxSignedXstsRequest
        {
            UserToken = "user-token",
            DeviceToken = "device-token",
            TitleToken = "title-token",
            OptionalDisplayClaims = new[] { "xui", "xti" }
        };

        var response = await request.Send(client, signer);

        Assert(response.Token == "signed-result", "response token was not deserialized");
        Assert(handler.Request!.RequestUri!.AbsoluteUri == "https://xsts.auth.xboxlive.com/xsts/authorize", "signed URL changed");
        Assert(handler.Body == signer.Body, "signature input body differs from wire body");
        Assert(signer.RequestUri == handler.Request.RequestUri.AbsoluteUri, "signer URI differs from wire URI");
        Assert(signer.Token == string.Empty, "signed XSTS must sign an empty token field");
        using var body = JsonDocument.Parse(handler.Body!);
        var root = body.RootElement;
        Assert(root.GetProperty("RelyingParty").GetString() == "http://xboxlive.com", "signed default relying party changed");
        Assert(root.GetProperty("TokenType").GetString() == "JWT", "signed token type changed");
        var props = root.GetProperty("Properties");
        Assert(props.GetProperty("UserTokens")[0].GetString() == "user-token", "user token not forwarded");
        Assert(props.GetProperty("DeviceToken").GetString() == "device-token", "device token not forwarded");
        Assert(props.GetProperty("TitleToken").GetString() == "title-token", "title token not forwarded");
        Assert(props.GetProperty("OptionalDisplayClaims")[1].GetString() == "xti", "display claims not forwarded");
        Assert(props.GetProperty("SandboxId").GetString() == "RETAIL", "sandbox contract changed");
        Assert(!props.TryGetProperty("ProofKey", out _), "proof key must stay out of the delegated XSTS property bag");
        Assert(handler.Request.Headers.TryGetValues("Signature", out var signatures) && signatures.Single() == "synthetic-signature", "signature header missing");
        Assert(handler.Request.Headers.GetValues("x-xbl-contract-version").Single() == "1", "signed contract version must be 1");
        Assert(handler.Request.Headers.GetValues("Accept").Single() == "application/json", "common headers missing");
    }

    private static async Task UnsignedXstsDefaultsToXboxLiveRp()
    {
        var handler = new CaptureHandler(Json("Token", "unsigned-result"));
        using var client = new HttpClient(handler);
        var response = await new XboxXstsRequest { UserToken = "user-token" }.Send(client);
        Assert(response.Token == "unsigned-result", "unsigned response not deserialized");
        Assert(handler.Request!.Headers.GetValues("x-xbl-contract-version").Single() == "1", "contract version must be 1");
        using var body = JsonDocument.Parse(handler.Body!);
        Assert(body.RootElement.GetProperty("RelyingParty").GetString() == XboxAuthConstants.XboxLiveRelyingParty, "unsigned default RP changed");
        Assert(body.RootElement.GetProperty("Properties").GetProperty("UserTokens")[0].GetString() == "user-token", "unsigned user token missing");
    }

    private static Task XboxAppPresenceRpIsExplicit()
    {
        Assert(XboxAuthConstants.XboxAppRelyingParty == "https://xboxlive.com", "Xbox App RP candidate changed");
        Assert(XboxAuthConstants.XboxLiveRelyingParty == "http://xboxlive.com", "legacy RP default changed");
        return Task.CompletedTask;
    }

    private static async Task UnsignedXstsCarriesAllTokenInputs()
    {
        var handler = new CaptureHandler(Json("Token", "presence-result"));
        using var client = new HttpClient(handler);
        await new XboxXstsRequest
        {
            UserToken = "user-token",
            DeviceToken = "device-token",
            TitleToken = "title-token",
            OptionalDisplayClaims = new[] { "xui", "xti" }
        }.Send(client);
        using var body = JsonDocument.Parse(handler.Body!);
        var root = body.RootElement;
        Assert(root.GetProperty("RelyingParty").GetString() == XboxAuthConstants.XboxLiveRelyingParty, "service RP not forwarded");
        var props = root.GetProperty("Properties");
        Assert(props.GetProperty("DeviceToken").GetString() == "device-token", "device token missing");
        Assert(props.GetProperty("TitleToken").GetString() == "title-token", "title token missing");
        Assert(props.GetProperty("OptionalDisplayClaims")[0].GetString() == "xui", "display claim missing");
    }

    private static Task PresenceTitleRequestUsesWireShape()
    {
        var json = JsonSerializer.Serialize(new PresenceTitleRequest { id = "0012345678" });
        using var body = JsonDocument.Parse(json);
        var root = body.RootElement;
        Assert(root.GetProperty("id").ValueKind == JsonValueKind.String, "presence title id must be a JSON string");
        Assert(root.GetProperty("id").GetString() == "0012345678", "presence title id spelling changed");
        Assert(root.GetProperty("state").GetString() == "active", "presence state changed");
        Assert(root.GetProperty("placement").GetString() == "full", "presence placement changed");
        return Task.CompletedTask;
    }

    private static Task NativePresenceStateRequestUsesWireShape()
    {
        var json = JsonSerializer.Serialize(new PresenceStateRequest());
        using var body = JsonDocument.Parse(json);
        var root = body.RootElement;
        Assert(root.GetProperty("state").GetString() == "active", "native presence state changed");
        Assert(root.EnumerateObject().Count() == 1, "native presence body must contain only state");
        return Task.CompletedTask;
    }

    private static async Task SisuNativeContractAndFields()
    {
        var handler = new CaptureHandler(Json("Token", "sisu-result"));
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256", key = "synthetic-proof-key" });
        await new XboxSisuAuthRequest
        {
            Profile = XboxSisuProfile.NativeContextV2,
            AccessToken = "access",
            ClientId = "XboxAppPC",
            DeviceToken = "device",
            TitleId = "704208617",
            SessionId = "session",
            UcsCheckinToken = "checkin",
            UcsWebToken = "web",
            UserPrompts = new[] { "a" },
            RequestConsent = true
        }.Send(client, signer);
        Assert(handler.Request!.Headers.GetValues("x-xbl-contract-version").Single() == "2", "SISU native contract must be 2");
        using var body = JsonDocument.Parse(handler.Body!);
        var root = body.RootElement;
        Assert(root.GetProperty("TitleId").GetString() == "704208617", "SISU title id missing");
        Assert(root.GetProperty("SessionId").GetString() == "session", "SISU session id missing");
        Assert(root.GetProperty("UcsCheckinToken").GetString() == "checkin", "SISU UCS checkin missing");
        Assert(root.GetProperty("UcsWebToken").GetString() == "web", "SISU UCS web token missing");
        Assert(root.GetProperty("Flow").GetString() == "consent", "SISU Flow=consent missing");
        Assert(!root.TryGetProperty("consent", out _), "consent is a value, not the native JSON key");
        var expectedOrder = new[] { "AccessToken", "AppId", "TitleId", "DeviceToken", "Sandbox",
            "UseModernGamertag", "SiteName", "RelyingParty", "SessionId", "UcsCheckinToken",
            "UcsWebToken", "UserPrompts", "Flow", "ProofKey" };
        Assert(root.EnumerateObject().Select(p => p.Name).SequenceEqual(expectedOrder), "native SISU field order changed");
        Assert(handler.Body == signer.Body, "native SISU signature input differs from wire body");
        Assert(signer.Token == string.Empty, "native SISU must sign an empty token field");
        Assert(handler.Request.Headers.GetValues("Signature").Single() == "synthetic-signature", "native SISU signature header missing");
    }

    private static async Task SisuOAuthDefaultPreservesBaseline()
    {
        var handler = new CaptureHandler("{}");
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256", key = "synthetic-proof-key" });
        var request = new XboxSisuAuthRequest
        {
            AccessToken = "synthetic-access",
            ClientId = "synthetic-app",
            DeviceToken = "synthetic-device"
        };
        Assert(request.Profile == XboxSisuProfile.OAuthCompatibility, "SISU default profile changed");
        await request.Send(client, signer);

        const string baselineBody = "{\"AccessToken\":\"t=synthetic-access\",\"AppId\":\"synthetic-app\",\"DeviceToken\":\"synthetic-device\",\"Sandbox\":\"RETAIL\",\"UseModernGamertag\":true,\"SiteName\":\"user.auth.xboxlive.com\",\"RelyingParty\":\"http://xboxlive.com\",\"ProofKey\":{\"alg\":\"ES256\",\"key\":\"synthetic-proof-key\"}}";
        Assert(handler.Body == baselineBody, "default SISU body differs from the compatibility baseline");
        Assert(signer.Body == baselineBody, "default SISU signer body differs from the compatibility baseline");
        Assert(handler.Request!.RequestUri!.AbsoluteUri == "https://sisu.xboxlive.com/authorize", "default SISU endpoint changed");
        Assert(signer.RequestUri == handler.Request.RequestUri.AbsoluteUri, "default SISU signer URI differs from the endpoint");
        Assert(signer.Token == string.Empty, "default SISU must sign an empty token field");
        Assert(handler.Request.Method == HttpMethod.Post, "default SISU method changed");
        Assert(handler.Request.Headers.GetValues("x-xbl-contract-version").Single() == "1", "default SISU contract must be 1");
        Assert(handler.Request.Headers.GetValues("Signature").Single() == "synthetic-signature", "default SISU signature header missing");
        Assert(handler.Request.Headers.GetValues("Accept").Single() == "application/json", "default SISU common headers missing");
        Assert(handler.Request.Content!.Headers.ContentType!.MediaType == "application/json", "default SISU content type changed");
    }

    private static async Task SisuOAuthDefaultOmitsNullFields()
    {
        var handler = new CaptureHandler("{}");
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256" });
        await new XboxSisuAuthRequest { AccessToken = "synthetic-access", Sandbox = null }.Send(client, signer);
        const string baselineBody = "{\"AccessToken\":\"t=synthetic-access\",\"UseModernGamertag\":true,\"SiteName\":\"user.auth.xboxlive.com\",\"RelyingParty\":\"http://xboxlive.com\",\"ProofKey\":{\"alg\":\"ES256\"}}";
        Assert(handler.Body == baselineBody && signer.Body == baselineBody, "optional null fields changed the compatibility body");
    }

    private static async Task SisuNativeTitleIdsAreCanonical()
    {
        foreach (var (input, expected) in new[] {
            ("000704208617", "704208617"), ("0", "0"),
            ("18446744073709551615", "18446744073709551615") })
        {
            var handler = new CaptureHandler("{}");
            using var client = new HttpClient(handler);
            var signer = new RecordingSigner(new { alg = "ES256" });
            await new XboxSisuAuthRequest {
                Profile = XboxSisuProfile.NativeContextV2, AccessToken = "synthetic-access", TitleId = input
            }.Send(client, signer);
            using var body = JsonDocument.Parse(handler.Body!);
            var title = body.RootElement.GetProperty("TitleId");
            Assert(title.ValueKind == JsonValueKind.String && title.GetString() == expected, "native SISU title ID is not canonical");
            Assert(handler.Body == signer.Body, "canonical title ID differs between signer and transport");
            Assert(handler.Request!.Headers.GetValues("x-xbl-contract-version").Single() == "2", "native SISU title used a nonnative contract");
        }
    }

    private static async Task SisuNativeRejectsInvalidTitleIds()
    {
        foreach (var titleId in new string?[] { null, "", " ", " 704208617", "704208617 ",
            "+704208617", "-1", "704208617.0", "704,208,617", "0x29f960e9", "1e3",
            "18446744073709551616", "synthetic-invalid-title", "７０４２０８６１７" })
        {
            await AssertSisuRejectedBeforeSend(new XboxSisuAuthRequest {
                Profile = XboxSisuProfile.NativeContextV2, AccessToken = "synthetic-access", TitleId = titleId
            }, "invalid native SISU title ID");
        }
    }

    private static async Task SisuOAuthRejectsNativeContext()
    {
        var configureFields = new Action<XboxSisuAuthRequest>[] {
            request => request.TitleId = "704208617",
            request => request.TitleId = "",
            request => request.SessionId = "synthetic-session",
            request => request.SessionId = "",
            request => request.UcsCheckinToken = "synthetic-checkin",
            request => request.UcsCheckinToken = "",
            request => request.UcsWebToken = "synthetic-web",
            request => request.UcsWebToken = "",
            request => request.UserPrompts = new[] { "synthetic-prompt" },
            request => request.UserPrompts = Array.Empty<string>(),
            request => request.RequestConsent = true
        };
        foreach (var configure in configureFields)
        {
            var request = new XboxSisuAuthRequest { AccessToken = "synthetic-access" };
            configure(request);
            await AssertSisuRejectedBeforeSend(request, "native-only context on the OAuth compatibility profile");
        }
    }

    private static async Task SisuOAuthRejectsCopiedContinuation()
    {
        foreach (var (session, cluster) in new[] {
            ("synthetic-session", (string?)null),
            ((string?)null, "https://cluster.sisu.xboxlive.com"),
            ("synthetic-session", "https://cluster.sisu.xboxlive.com") })
        {
            using var response = SisuResponse(HttpStatusCode.OK, "{}", session, cluster);
            var context = (await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response)).Context!;
            var request = new XboxSisuAuthRequest { AccessToken = "synthetic-access" };
            request.ContinueFrom(context);
            Assert(request.SessionId == session && request.ClusterAffinity == cluster, "ContinueFrom failed to copy context on the default profile");
            await AssertSisuRejectedBeforeSend(request, "copied native continuation on the OAuth compatibility profile");
        }
    }

    private static async Task AssertSisuRejectedBeforeSend(XboxSisuAuthRequest request, string scenario)
    {
        var handler = new CaptureHandler("{}");
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256" });
        try
        {
            await request.Send(client, signer);
        }
        catch (InvalidOperationException error)
        {
            Assert(handler.Request == null, scenario + " reached HTTP transport");
            Assert(signer.Body == null, scenario + " reached signing");
            foreach (var secret in new[] { request.AccessToken, request.DeviceToken, request.SessionId,
                request.UcsCheckinToken, request.UcsWebToken })
                if (!string.IsNullOrEmpty(secret))
                    Assert(!error.Message.Contains(secret, StringComparison.Ordinal), "SISU preflight error exposed request context");
            return;
        }
        throw new InvalidOperationException(scenario + " was accepted");
    }

    private static async Task SisuResponseModernGamertagFlags()
    {
        foreach (var name in new[] { "UseModernGamertag", "UseModernGamerTag" })
        foreach (var expected in new[] { true, false })
        {
            var body = "{\"" + name + "\":" + (expected ? "true" : "false")
                + ",\"UserToken\":{\"Token\":\"synthetic-user\"},\"TitleToken\":{\"Token\":\"synthetic-title\"}}";
            using var response = SisuResponse(HttpStatusCode.OK, body);
            var result = await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
            Assert(result.UseModernGamertag == expected, "SISU successful response lost the boolean gamertag flag");
            Assert(result.UserToken?.Token == "synthetic-user" && result.TitleToken?.Token == "synthetic-title", "SISU boolean flag disrupted successful response tokens");
            Assert(result.Context?.SessionId == "synthetic-session", "SISU boolean flag disrupted successful response context");
            using var serialized = JsonDocument.Parse(JsonSerializer.Serialize(result));
            Assert(serialized.RootElement.GetProperty("UseModernGamertag").GetBoolean() == expected, "SISU flag did not serialize under the canonical key");
            Assert(!serialized.RootElement.TryGetProperty("UseModernGamerTag", out _), "legacy SISU response alias serialized a second flag");
        }
        using var absentResponse = SisuResponse(HttpStatusCode.OK, "{}", null, null);
        var absent = await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(absentResponse);
        Assert(absent.UseModernGamertag == null, "missing SISU gamertag flag became a boolean value");
    }

    private static async Task SisuMalformedSuccessMetadata()
    {
        foreach (var name in new[] { "UseModernGamertag", "UseModernGamerTag" })
        foreach (var malformedValue in new[] { "\"synthetic-secret-ç\"", "42" })
        {
            const string secret = "synthetic-secret-ç";
            var body = "{\"" + name + "\":" + malformedValue + ",\"UserToken\":{\"Token\":\"" + secret + "\"}}";
            using var response = SisuResponse(HttpStatusCode.OK, body);
            try
            {
                await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
            }
            catch (XboxAuthException error)
            {
                Assert(error.StatusCode == 200, "malformed successful SISU response lost its HTTP status");
                Assert(error.FailureKind == "invalid_response" && error.Error == "invalid_response", "SISU parse failure became a service error");
                Assert(error.ResponseBodyBytes == Encoding.UTF8.GetByteCount(body), "SISU parse failure byte count is not UTF-8");
                Assert(error.SisuContext == null, "malformed SISU success captured continuation");
                Assert(!error.ToString().Contains(secret, StringComparison.Ordinal), "SISU parse failure exposed response token content");
                continue;
            }
            throw new InvalidOperationException("nonboolean SISU response flag was accepted");
        }
    }

    private static HttpResponseMessage SisuResponse(HttpStatusCode status, string body,
        string? session = "synthetic-session", string? cluster = "https://cluster.sisu.xboxlive.com")
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };
        if (session != null) response.Headers.TryAddWithoutValidation("x-sessionid", session);
        if (cluster != null) response.Headers.TryAddWithoutValidation("X-Cluster-Affinity", cluster);
        return response;
    }

    private static async Task SisuResponseRetainsContinuation()
    {
        using var response = SisuResponse(HttpStatusCode.OK, "{\"UserToken\":{\"Token\":\"u\"},\"TitleToken\":{\"Token\":\"t\"}}");
        var result = await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
        Assert(result.Context?.SessionId == "synthetic-session", "session header discarded");
        Assert(result.Context?.ClusterAffinity == "https://cluster.sisu.xboxlive.com", "affinity header discarded");
        Assert(!JsonSerializer.Serialize(result).Contains("synthetic-session"), "continuation leaked into response JSON");
        var request = new XboxSisuAuthRequest {
            Profile = XboxSisuProfile.NativeContextV2, AccessToken = "access", TitleId = "704208617"
        };
        request.ContinueFrom(result.Context!);
        var transport = new CaptureHandler("{}");
        using var client = new HttpClient(transport);
        var signer = new RecordingSigner(new { alg = "ES256" });
        await request.Send(client, signer);
        Assert(transport.Request!.RequestUri!.AbsoluteUri == "https://cluster.sisu.xboxlive.com/authorize", "affinity not used");
        Assert(signer.RequestUri == transport.Request.RequestUri.AbsoluteUri, "signature URL differs from destination");
        Assert(signer.Body == transport.Body, "signature body differs from wire body");
        using var json = JsonDocument.Parse(transport.Body!);
        Assert(json.RootElement.GetProperty("SessionId").GetString() == "synthetic-session", "continuation body lost session");
        Assert(!json.RootElement.TryGetProperty("ClusterAffinity", out _), "routing context entered body");
    }

    private static async Task SisuChallengeRetainsContext()
    {
        using var response = SisuResponse(HttpStatusCode.Unauthorized, "{\"WebPage\":\"https://example.invalid/consent\"}");
        try
        {
            await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
            throw new InvalidOperationException("401 challenge became success");
        }
        catch (XboxAuthException error)
        {
            Assert(error.StatusCode == 401, "challenge status discarded");
            Assert(error.SisuContext?.SessionId == "synthetic-session", "challenge lost operation context");
            Assert(!error.Message.Contains("synthetic-session"), "context entered error message");
        }
    }

    private static async Task SisuErrorsWithoutWebPage()
    {
        foreach (var item in new[] {
            (HttpStatusCode.Unauthorized, "{}"),
            (HttpStatusCode.Unauthorized, "{\"WebPage\":\"\"}"),
            (HttpStatusCode.Unauthorized, "{\"WebPage\":42}"),
            (HttpStatusCode.Forbidden, "{\"WebPage\":\"page\"}"),
            (HttpStatusCode.Unauthorized, "not-json") })
        {
            using var response = SisuResponse(item.Item1, item.Item2);
            try
            {
                await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
                throw new InvalidOperationException("error became success");
            }
            catch (XboxAuthException error)
            {
                Assert(error.StatusCode == (int)item.Item1, "HTTP error status changed");
                Assert(error.SisuContext == null, "nonchallenge captured continuation");
            }
        }
    }

    private static async Task SisuContinuationClearsMissingFields()
    {
        using var first = SisuResponse(HttpStatusCode.OK, "{}");
        using var empty = SisuResponse(HttpStatusCode.OK, "{}", null, null);
        var parser = new XboxAuthResponseHandler();
        var request = new XboxSisuAuthRequest {
            Profile = XboxSisuProfile.NativeContextV2, AccessToken = "access", TitleId = "704208617"
        };
        request.ContinueFrom((await parser.HandleResponse<XboxSisuResponse>(first)).Context!);
        request.ContinueFrom((await parser.HandleResponse<XboxSisuResponse>(empty)).Context!);
        Assert(request.SessionId == null && request.ClusterAffinity == null, "missing response fields reused old context");
        var transport = new CaptureHandler("{}");
        using var client = new HttpClient(transport);
        await request.Send(client, new RecordingSigner(new { alg = "ES256" }));
        Assert(transport.Request!.RequestUri!.Host == "sisu.xboxlive.com", "missing affinity did not restore default route");
        using var body = JsonDocument.Parse(transport.Body!);
        Assert(!body.RootElement.TryGetProperty("SessionId", out _), "missing session serialized");
    }

    private static async Task SisuAffinityRejectsUnrelatedEndpoints()
    {
        foreach (var endpoint in new[] { "https://example.invalid", "http://sisu.xboxlive.com",
            "https://sisu.xboxlive.com.example.invalid", "https://sisu.xboxlive.com:444",
            "https://user@sisu.xboxlive.com", "https://sisu.xboxlive.com/path",
            "https://sisu.xboxlive.com/?q=1", "https://sisu.xboxlive.com/#fragment" })
        {
            using var response = SisuResponse(HttpStatusCode.OK, "{}", "new-session", endpoint);
            var context = (await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response)).Context!;
            var request = new XboxSisuAuthRequest {
                Profile = XboxSisuProfile.NativeContextV2, TitleId = "704208617", SessionId = "old-session"
            };
            try
            {
                request.ContinueFrom(context);
                throw new Exception("unrelated endpoint accepted");
            }
            catch (InvalidOperationException)
            {
                Assert(request.SessionId == "old-session" && request.ClusterAffinity == null, "rejected continuation partly mutated request");
            }
        }
    }

    private static async Task SisuPartialContextIsOmitted()
    {
        foreach (var item in new[] { ("checkin", (string?)null), ((string?)null, "web"), ("", "web") })
        {
            var transport = new CaptureHandler("{}");
            using var client = new HttpClient(transport);
            await new XboxSisuAuthRequest {
                Profile = XboxSisuProfile.NativeContextV2, TitleId = "704208617",
                AccessToken = "access", SessionId = "", UcsCheckinToken = item.Item1,
                UcsWebToken = item.Item2, UserPrompts = new[] { "prompt" }, RequestConsent = true
            }.Send(client, new RecordingSigner(new { alg = "ES256" }));
            using var body = JsonDocument.Parse(transport.Body!);
            foreach (var key in new[] { "SessionId", "UcsCheckinToken", "UcsWebToken", "UserPrompts", "Flow" })
                Assert(!body.RootElement.TryGetProperty(key, out _), "partial context emitted " + key);
        }
        var paired = new CaptureHandler("{}");
        using var pairedClient = new HttpClient(paired);
        await new XboxSisuAuthRequest {
            Profile = XboxSisuProfile.NativeContextV2, TitleId = "704208617",
            AccessToken = "access", UcsCheckinToken = "c", UcsWebToken = "w"
        }
            .Send(pairedClient, new RecordingSigner(new { alg = "ES256" }));
        using var pairedBody = JsonDocument.Parse(paired.Body!);
        Assert(pairedBody.RootElement.GetProperty("UserPrompts").GetArrayLength() == 0, "paired context requires prompts array");
        Assert(!pairedBody.RootElement.TryGetProperty("Flow", out _), "consent flow invented without request");
    }

    private static Task SisuContextBounds()
    {
        foreach (var values in new[] { new[] { "a", "b" }, new[] { new string('x', 4097) }, new[] { "a\tb" } })
        {
            using var response = SisuResponse(HttpStatusCode.OK, "{}", null, null);
            response.Headers.TryAddWithoutValidation("X-SessionId", values);
            try
            {
                XboxSisuContext.FromHeaders(response.Headers);
                throw new InvalidOperationException("invalid context accepted");
            }
            catch (JsonException error)
            {
                Assert(error.Message == "Invalid SISU X-SessionId header", "invalid context appeared in error message");
            }
        }
        return Task.CompletedTask;
    }

    private static async Task SisuConcurrentContextsAreSeparate()
    {
        var parser = new XboxAuthResponseHandler();
        async Task<XboxSisuContext?> Parse(string id)
        {
            using var response = SisuResponse(HttpStatusCode.Unauthorized, "{\"WebPage\":\"page\"}", id);
            response.Content = new YieldingContent("{\"WebPage\":\"page\"}");
            try { await parser.HandleResponse<XboxSisuResponse>(response); }
            catch (XboxAuthException error) { return error.SisuContext; }
            throw new InvalidOperationException("challenge became success");
        }
        var results = await Task.WhenAll(Parse("session-a"), Parse("session-b"));
        Assert(results[0]?.SessionId == "session-a" && results[1]?.SessionId == "session-b", "operation contexts mixed");
    }

    private static Task DisplayClaimsRetainsTitleAndSandbox()
    {
        var response = JsonSerializer.Deserialize<XboxAuthResponse>(
            "{\"DisplayClaims\":{\"xui\":[{\"uhs\":\"u\"}],\"xti\":{\"tid\":\"704208617\"},\"sbx\":\"RETAIL\"},\"Token\":\"t\",\"NotAfter\":\"2999-01-01T00:00:00Z\"}");
        Assert(response?.XuiClaims?.TitleId == "704208617", "xti.tid was discarded");
        Assert(response?.XuiClaims?.Sandbox == "RETAIL", "sbx was discarded");
        return Task.CompletedTask;
    }

    private static async Task NumericXErrIsHexadecimal()
    {
        var handler = new CaptureHandler(HttpStatusCode.BadRequest, "{\"XErr\":2148916233,\"Message\":\"synthetic\"}");
        using var client = new HttpClient(handler);
        try
        {
            await new XboxXstsRequest { UserToken = "user-token" }.Send(client);
            throw new InvalidOperationException("request unexpectedly succeeded");
        }
        catch (XboxAuthException ex)
        {
            Assert(ex.StatusCode == 400, "status code was not retained");
            Assert(ex.FailureKind == "http_error", "HTTP rejection became a local decode failure");
            Assert(ex.ResponseBodyBytes == Encoding.UTF8.GetByteCount("{\"XErr\":2148916233,\"Message\":\"synthetic\"}"), "HTTP rejection byte count changed");
            Assert(ex.Error == "8015dc09", $"numeric XErr conversion changed: {ex.Error}");
            Assert(ex.ErrorMessage == "synthetic", "error message was not retained");
        }
    }

    private static async Task HeaderXErrIsHexadecimal()
    {
        var handler = new CaptureHandler(HttpStatusCode.Forbidden, "forbidden");
        handler.ResponseHeaders.Add("X-Err", "2148916233");
        using var client = new HttpClient(handler);
        try
        {
            await new XboxXstsRequest { UserToken = "user-token" }.Send(client);
            throw new InvalidOperationException("request unexpectedly succeeded");
        }
        catch (XboxAuthException ex)
        {
            Assert(ex.StatusCode == 403, "header status code was not retained");
            Assert(ex.FailureKind == "http_error", "header HTTP rejection became a local decode failure");
            Assert(ex.ResponseBodyBytes == Encoding.UTF8.GetByteCount("forbidden"), "header HTTP rejection byte count changed");
            Assert(ex.Error == "8015dc09", $"header XErr conversion changed: {ex.Error}");
        }
    }

    private static string Json(string property, string value) => $"{{\"{property}\":\"{value}\",\"NotAfter\":\"2999-01-01T00:00:00Z\"}}";

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class RecordingSigner : IXboxRequestSigner
    {
        public RecordingSigner(object proofKey) => ProofKey = proofKey;
        public object ProofKey { get; }
        public string? RequestUri { get; private set; }
        public string? Token { get; private set; }
        public string? Body { get; private set; }
        public string SignRequest(string reqUri, string token, string body)
        {
            RequestUri = reqUri;
            Token = token;
            Body = body;
            return "synthetic-signature";
        }
    }

    private sealed class YieldingContent : HttpContent
    {
        private readonly byte[] _bytes;
        public YieldingContent(string value) => _bytes = Encoding.UTF8.GetBytes(value);
        protected override bool TryComputeLength(out long length) { length = _bytes.Length; return true; }
        protected override async Task SerializeToStreamAsync(System.IO.Stream stream, TransportContext? context)
        {
            await Task.Yield();
            await stream.WriteAsync(_bytes);
        }
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;
        public CaptureHandler(string body) : this(HttpStatusCode.OK, body) { }
        public CaptureHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }
        public HttpRequestMessage? Request { get; private set; }
        public string? Body { get; private set; }
        public HttpResponseHeaders ResponseHeaders { get; } = new HttpResponseMessage().Headers;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content == null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            var response = new HttpResponseMessage(_status)
            {
                RequestMessage = request,
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            };
            foreach (var header in ResponseHeaders)
                response.Headers.TryAddWithoutValidation(header.Key, header.Value);
            return response;
        }
    }
}

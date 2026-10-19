using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.DeviceRps;
using XboxAuthNet.XboxLive.Requests;

internal static class Program
{
    private static readonly Guid OwnId = new("4aaf3514-14bb-47e1-90ee-c7196c6c1227");
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-19T01:00:00Z");
    private const string Secret = "synthetic-secret-never-log";
    private static int _passed;

    public static async Task<int> Main()
    {
        await Run("PoP profiles remain unchanged and default", PopProfiles);
        await Run("RPS is explicit, ordered, opaque and omits anonymous fields", RpsWire);
        await Run("RPS optional version and mixed-profile rejection", ProfilesRejectInvalid);
        await Run("caller-owned ApplicationId is explicit", ApplicationIdExplicit);
        await Run("provider exchanges once using the exact public key and signature", SuccessAndSignature);
        await Run("acquisition gates reject failure, empty and inconsistent tickets without HTTP", AcquisitionGates);
        await Run("invalid/private proof keys fail before acquisition or HTTP", ProofKeyGates);
        await Run("response acceptance requires HTTP, object, XErr, token and lifetime", ResponseGates);
        await Run("HTTP errors retain only safe status/XErr metadata", ErrorRedaction);
        await Run("oversized bodies stop after the bounded response limit", ResponseBound);
        await Run("provider/signature/transport failures never retain secret exceptions", OperationalFailures);
        await Run("cancellation aborts acquisition/exchange without fallback", Cancellation);
        await Run("credential containers and request serialization redact values", SerializationRedaction);
        await Run("simultaneous exchanges keep their tickets and keys separate", ConcurrentIsolation);
        Console.WriteLine($"PASS: {_passed} offline DeviceRPS test groups; no OS acquisition or service I/O");
        return 0;
    }

    private static async Task Run(string name, Func<Task> test)
    {
        await test();
        _passed++;
        Console.WriteLine("PASS " + name);
    }

    private static Task PopProfiles()
    {
        var request = new ExposedRequest { DeviceType = "Win32", DeviceVersion = "0.0.0",
            Id = "11111111-2222-3333-4444-555555555555", SerialNumber = "66666666-7777-8888-9999-aaaaaaaaaaaa" };
        Assert(request.AuthenticationMethod == XboxDeviceAuthenticationMethod.ProofOfPossession, "PoP default");
        using var legacy = request.Body(new { key = "public" });
        Assert(Names(legacy.RootElement) == "Properties,RelyingParty,TokenType", "legacy outer order");
        var properties = legacy.RootElement.GetProperty("Properties");
        Assert(Names(properties) == "AuthMethod,Id,DeviceType,SerialNumber,Version,ProofKey", "legacy fields/order");
        Assert(properties.GetProperty("AuthMethod").GetString() == "ProofOfPossession", "legacy method");
        request.NativeWin32Profile = true;
        request.SerialNumber = null;
        using var native = request.Body(new { key = "public" });
        Assert(Names(native.RootElement.GetProperty("Properties")) == "AuthMethod,Id,DeviceType,Version,ProofKey", "native optional serial");
        return Task.CompletedTask;
    }

    private static Task RpsWire()
    {
        foreach (var ticket in new[] { "opaque", "t=" + Secret, "d=" + Secret, "t=é\"\n\\" })
        {
            var request = new ExposedRequest { AuthenticationMethod = XboxDeviceAuthenticationMethod.DeviceRps, RpsTicket = ticket };
            using var json = request.Body(new { key = "public" });
            Assert(Names(json.RootElement) == "RelyingParty,TokenType,Properties", "RPS outer order");
            Assert(json.RootElement.GetProperty("RelyingParty").GetString() == "http://auth.xboxlive.com", "device relying party");
            Assert(json.RootElement.GetProperty("TokenType").GetString() == "JWT", "device token type");
            var properties = json.RootElement.GetProperty("Properties");
            Assert(Names(properties) == "AuthMethod,RpsTicket,SiteName,ProofKey", "RPS properties/order");
            Assert(properties.GetProperty("AuthMethod").GetString() == "RPS", "RPS method");
            Assert(properties.GetProperty("RpsTicket").GetString() == ticket, "opaque ticket preserved");
            Assert(properties.GetProperty("SiteName").GetString() == "user.auth.xboxlive.com", "site");
        }
        return Task.CompletedTask;
    }

    private static Task ProfilesRejectInvalid()
    {
        var optional = new ExposedRequest { AuthenticationMethod = XboxDeviceAuthenticationMethod.DeviceRps,
            RpsTicket = Secret, DeviceVersion = "10.0.19041" };
        using var json = optional.Body(new { key = "public" });
        Assert(Names(json.RootElement.GetProperty("Properties")) == "AuthMethod,RpsTicket,SiteName,Version,ProofKey", "optional version");
        foreach (var mutate in new Action<ExposedRequest>[]
        {
            r => r.NativeWin32Profile = true, r => r.Id = "", r => r.SerialNumber = "x", r => r.DeviceType = "Win32",
            r => r.RpsTicket = null, r => r.RpsTicket = "", r => r.RelyingParty = null,
            r => r.AuthenticationMethod = (XboxDeviceAuthenticationMethod)99
        })
        {
            var request = new ExposedRequest { AuthenticationMethod = XboxDeviceAuthenticationMethod.DeviceRps, RpsTicket = Secret };
            mutate(request);
            Throws<InvalidOperationException>(() => request.Body(new { key = "public" }));
        }
        Throws<InvalidOperationException>(() => new ExposedRequest { DeviceType = "Win32", DeviceVersion = "0", RpsTicket = Secret }.Body(new { }));
        return Task.CompletedTask;
    }

    private static Task ApplicationIdExplicit()
    {
        Throws<ArgumentException>(() => new DeviceRpsTicketRequest(Guid.Empty));
        Assert(new DeviceRpsTicketRequest(OwnId).ApplicationId == OwnId, "explicit app id");
        Assert(DeviceRpsTicketRequest.Service == "service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0", "one-string service contract");
        return Task.CompletedTask;
    }

    private static async Task SuccessAndSignature()
    {
        using var key = new SyntheticKey();
        var opaqueTicket = "t=" + Secret + "é\"\n\\";
        var tickets = new FakeTickets(opaqueTicket);
        using var handler = new FakeHandler(SuccessBody());
        using var client = new HttpClient(handler);
        var result = await Provider(tickets).AcquireAsync(new DeviceRpsTicketRequest(OwnId), client,
            new XboxRequestSigner(key), deviceVersion: "10.0.19041");
        Assert(result.Token.Token == Secret && result.Acquisition.Accepted && result.Response.Accepted, "accepted result");
        Assert(tickets.Calls == 1 && tickets.Request?.ApplicationId == OwnId && handler.Calls == 1, "one acquire/exchange and explicit app identity");
        Assert(handler.Method == "POST" && handler.Url == DeviceRpsTokenProvider.Endpoint, "fixed endpoint/method");
        Assert(handler.Authorization == null && handler.Contract == "1", "empty auth token and contract 1");
        Assert(handler.Body!.All(c => c <= 127), "JSON escape preserves ASCII signer compatibility");
        using var body = JsonDocument.Parse(handler.Body!);
        var properties = body.RootElement.GetProperty("Properties");
        Assert(properties.GetProperty("RpsTicket").GetString() == opaqueTicket, "ticket transmitted unchanged");
        var header = Convert.FromBase64String(handler.Signature!);
        var payload = CanonicalPayload(handler.Body!, header);
        Assert(key.LastPayload!.SequenceEqual(payload), "exact wire body is signed");
        var proof = properties.GetProperty("ProofKey");
        using var publicKey = PublicKey(proof);
        Assert(publicKey.VerifyData(payload, header.AsSpan(12), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "signature verifies with the request JWK");
        payload[^2] ^= 1;
        Assert(!publicKey.VerifyData(payload, header.AsSpan(12), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "body tamper fails verification");
        using var other = new SyntheticKey();
        Assert(!other.Verify(CanonicalPayload(handler.Body!, header), header.AsSpan(12)), "unrelated key fails verification");
        Assert(!JsonSerializer.Serialize(result).Contains(Secret), "result JSON redacted");
        Assert(!Newtonsoft.Json.JsonConvert.SerializeObject(result).Contains(Secret), "Newtonsoft result JSON redacted");
    }

    private static async Task AcquisitionGates()
    {
        var invalid = new[]
        {
            new DeviceRpsAcquisitionMetadata(false, null, null, false, false, null, 0),
            new DeviceRpsAcquisitionMetadata(true, 1, null, false, false, null, 0),
            new DeviceRpsAcquisitionMetadata(true, 0, unchecked((int)0x80004005), true, true, 0, Secret.Length),
            new DeviceRpsAcquisitionMetadata(true, 0, null, false, true, 0, Secret.Length),
            new DeviceRpsAcquisitionMetadata(true, 0, null, true, false, 0, Secret.Length),
            new DeviceRpsAcquisitionMetadata(true, 0, null, true, true, 7, Secret.Length),
            new DeviceRpsAcquisitionMetadata(true, 0, null, true, true, null, Secret.Length),
            new DeviceRpsAcquisitionMetadata(true, 0, null, true, true, 0, 0),
            new DeviceRpsAcquisitionMetadata(true, 0, null, true, true, 0, Secret.Length + 1)
        };
        using var key = new SyntheticKey();
        foreach (var metadata in invalid)
        {
            var tickets = new FakeTickets((_, _) => Task.FromResult(new DeviceRpsTicket(metadata, Secret)));
            using var handler = new FakeHandler(SuccessBody());
            using var client = new HttpClient(handler);
            var error = await Fails(() => Provider(tickets).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key)));
            Assert(error.FailureKind == "acquisition_rejected" && handler.Calls == 0 && tickets.Calls == 1, "acquisition rejected without exchange/fallback");
            Assert(ReferenceEquals(error.Acquisition, metadata), "diagnostics retained");
        }
        foreach (var value in new string?[] { null, "" })
        {
            var tickets = new FakeTickets((_, _) => Task.FromResult(new DeviceRpsTicket(ValidMetadata(Secret.Length), value)));
            using var handler = new FakeHandler(SuccessBody());
            using var client = new HttpClient(handler);
            Assert((await Fails(() => Provider(tickets).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key)))).FailureKind == "acquisition_rejected", "missing value rejected");
            Assert(handler.Calls == 0, "no exchange");
        }
    }

    private static async Task ProofKeyGates()
    {
        foreach (var proof in new object[] { new { }, new { crv = "P-256", alg = "ES256", use = "sig", kty = "EC", x = new string('A', 43), y = new string('A', 43), d = Secret },
            new { crv = "P-384", alg = "ES256", use = "sig", kty = "EC", x = new string('A', 43), y = new string('A', 43) } })
        {
            var tickets = new FakeTickets(Secret);
            using var handler = new FakeHandler(SuccessBody());
            using var client = new HttpClient(handler);
            var error = await Fails(() => Provider(tickets).AcquireAsync(new(OwnId), client, new InvalidSigner(proof)));
            Assert(error.FailureKind == "invalid_proof_key" && tickets.Calls == 0 && handler.Calls == 0, "proof rejected before acquisition/exchange");
            Redacted(error);
        }
    }

    private static async Task ResponseGates()
    {
        var good = SuccessBody();
        var cases = new[]
        {
            (200, "not-json"), (200, "[]"), (200, "null"), (200, "{}"),
            (200, good.Replace(Secret, "")), (200, good.Replace("2026-10-19T02:00:00Z", "2026-10-19T00:30:00Z")),
            (200, good.Replace("2026-10-19T00:00:00Z", "2026-10-19T01:30:00Z")),
            (200, good.Replace("2026-10-19T02:00:00Z", "invalid")),
            (200, good.Replace("2026-10-19T02:00:00Z", "2026-10-19T02:00:00")),
            (200, good.Insert(1, "\"XErr\":1,")), (200, good.Insert(1, "\"XErr\":{},")),
            (200, good.Insert(1, "\"XErr\":-1,")), (200, good.Insert(1, "\"XErr\":4294967296,")),
            (200, good.Insert(1, "\"Token\":\"different\",")), (403, good), (302, good)
        };
        using var key = new SyntheticKey();
        foreach (var (status, body) in cases)
        {
            using var handler = new FakeHandler(body, status);
            using var client = new HttpClient(handler);
            var error = await Fails(() => Provider(new FakeTickets(Secret)).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key)));
            Assert(error.FailureKind == (status < 300 ? "invalid_response" : "http_error"), "response rejection class");
            Assert(error.Response?.StatusCode == status && !error.Response.Accepted && handler.Calls == 1, "status and rejection metadata");
            Redacted(error);
        }
        foreach (var xerr in new[] { "0", "\"0\"" })
        {
            using var handler = new FakeHandler(good.Insert(1, "\"XErr\":" + xerr + ","));
            using var client = new HttpClient(handler);
            Assert((await Provider(new FakeTickets(Secret)).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key))).Response.Accepted, "zero XErr accepted");
        }
    }

    private static async Task ErrorRedaction()
    {
        using var key = new SyntheticKey();
        using var handler = new FakeHandler("{\"XErr\":2148916233,\"Message\":\"" + Secret + "\",\"Redirect\":\"https://example.invalid/" + Secret + "\"}", 403);
        using var client = new HttpClient(handler);
        var error = await Fails(() => Provider(new FakeTickets(Secret)).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key)));
        Assert(error.Response?.StatusCode == 403 && error.Response.XErr == 2148916233 && error.Response.JsonObject, "safe HTTP/XErr metadata");
        Redacted(error);
        Assert(error.InnerException == null && !error.Data.Contains("body"), "no raw diagnostic attachments");
    }

    private static async Task ResponseBound()
    {
        using var key = new SyntheticKey();
        using var handler = new FakeHandler(new string('x', DeviceRpsTokenProvider.MaxResponseBytes + 2000));
        using var client = new HttpClient(handler);
        var error = await Fails(() => Provider(new FakeTickets(Secret)).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key)));
        Assert(error.FailureKind == "response_too_large" && error.Response?.ResponseTooLarge == true
            && error.Response.ResponseBytes == DeviceRpsTokenProvider.MaxResponseBytes + 1, "bounded response read");
    }

    private static async Task OperationalFailures()
    {
        using var key = new SyntheticKey();
        using var handler = new FakeHandler(SuccessBody());
        using var client = new HttpClient(handler);
        var providerError = await Fails(() => Provider(new FakeTickets((_, _) => throw new Exception(Secret)))
            .AcquireAsync(new(OwnId), client, new XboxRequestSigner(key)));
        Assert(providerError.FailureKind == "acquisition_exception" && handler.Calls == 0, "provider failure");
        Redacted(providerError);
        var signingError = await Fails(() => Provider(new FakeTickets(Secret)).AcquireAsync(new(OwnId), client,
            new InvalidSigner(key.ProofKey)));
        Assert(signingError.FailureKind == "request_signing_failed" && handler.Calls == 0, "signing failure");
        Redacted(signingError);
        using var failing = new FakeHandler((_, _) => throw new HttpRequestException(Secret));
        using var failingClient = new HttpClient(failing);
        var transportError = await Fails(() => Provider(new FakeTickets(Secret)).AcquireAsync(new(OwnId), failingClient, new XboxRequestSigner(key)));
        Assert(transportError.FailureKind == "transport_error" && failing.Calls == 1, "transport failure");
        Redacted(transportError);
    }

    private static async Task Cancellation()
    {
        using var key = new SyntheticKey();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var tickets = new FakeTickets(Secret);
        using var handler = new FakeHandler(SuccessBody());
        using var client = new HttpClient(handler);
        await ThrowsAsync<OperationCanceledException>(() => Provider(tickets).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key), cancellation.Token));
        Assert(tickets.Calls == 0 && handler.Calls == 0, "pre-cancellation does not acquire");
        using var during = new CancellationTokenSource();
        var cancels = new FakeTickets((_, token) => { Assert(token == during.Token, "token forwarded"); during.Cancel(); throw new OperationCanceledException(Secret, token); });
        var error = await ThrowsAsync<OperationCanceledException>(() => Provider(cancels).AcquireAsync(new(OwnId), client, new XboxRequestSigner(key), during.Token));
        Assert(!error.ToString().Contains(Secret) && error.InnerException == null && handler.Calls == 0, "cancellation redacted without exchange");
        using var exchangeCancellation = new CancellationTokenSource();
        using var canceledHandler = new FakeHandler((_, _) =>
        {
            exchangeCancellation.Cancel();
            throw new OperationCanceledException(Secret, exchangeCancellation.Token);
        });
        using var canceledClient = new HttpClient(canceledHandler);
        var exchangeError = await ThrowsAsync<OperationCanceledException>(() => Provider(new FakeTickets(Secret))
            .AcquireAsync(new(OwnId), canceledClient, new XboxRequestSigner(key), exchangeCancellation.Token));
        Assert(canceledHandler.Calls == 1 && !exchangeError.ToString().Contains(Secret)
            && exchangeError.InnerException == null, "exchange cancellation redacted without retry");
    }

    private static Task SerializationRedaction()
    {
        var ticket = new DeviceRpsTicket(ValidMetadata(Secret.Length), Secret);
        Assert(!JsonSerializer.Serialize(ticket).Contains(Secret) && !ticket.ToString().Contains(Secret), "ticket redacted");
        Assert(!Newtonsoft.Json.JsonConvert.SerializeObject(ticket).Contains(Secret), "Newtonsoft ticket JSON redacted");
        var request = new XboxDeviceTokenRequest { AuthenticationMethod = XboxDeviceAuthenticationMethod.DeviceRps, RpsTicket = Secret };
        Assert(!JsonSerializer.Serialize(request).Contains(Secret) && !request.ToString()!.Contains(Secret), "request credential redacted");
        Assert(!Newtonsoft.Json.JsonConvert.SerializeObject(request).Contains(Secret), "Newtonsoft request JSON redacted");
        return Task.CompletedTask;
    }

    private static async Task ConcurrentIsolation()
    {
        async Task<string> Exchange(string ticket)
        {
            using var key = new SyntheticKey();
            using var handler = new FakeHandler(SuccessBody());
            using var client = new HttpClient(handler);
            await Provider(new FakeTickets(async (_, _) => { await Task.Yield(); return new DeviceRpsTicket(ValidMetadata(ticket.Length), ticket); }))
                .AcquireAsync(new(OwnId), client, new XboxRequestSigner(key));
            using var body = JsonDocument.Parse(handler.Body!);
            return body.RootElement.GetProperty("Properties").GetProperty("RpsTicket").GetString()!;
        }
        var results = await Task.WhenAll(Exchange("t=first"), Exchange("d=second"));
        Assert(results.SequenceEqual(new[] { "t=first", "d=second" }), "no shared request/ticket state");
    }

    private static DeviceRpsTokenProvider Provider(IDeviceRpsTicketProvider tickets) => new(tickets, () => Now);
    private static DeviceRpsAcquisitionMetadata ValidMetadata(int length) => new(true, 0, null, true, true, 0, length);
    private static string SuccessBody() => "{\"Token\":\"" + Secret + "\",\"IssueInstant\":\"2026-10-19T00:00:00Z\",\"NotAfter\":\"2026-10-19T02:00:00Z\"}";
    private static string Names(JsonElement element) => string.Join(",", element.EnumerateObject().Select(p => p.Name));
    private static void Assert(bool value, string message) { if (!value) throw new Exception(message); }
    private static void Throws<T>(Action test) where T : Exception
    { try { test(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private static async Task<T> ThrowsAsync<T>(Func<Task> test) where T : Exception
    { try { await test(); } catch (T error) { return error; } throw new Exception("Expected " + typeof(T).Name); }
    private static Task<DeviceRpsException> Fails(Func<Task> test) => ThrowsAsync<DeviceRpsException>(test);
    private static void Redacted(DeviceRpsException error)
    {
        Assert(!error.ToString().Contains(Secret) && error.InnerException == null, "exception must redact credentials");
        Assert(!JsonSerializer.Serialize(new { error.Message, error.FailureKind, error.CauseHResult, error.Acquisition, error.Response }).Contains(Secret), "metadata serialization redacted");
    }

    private static byte[] CanonicalPayload(string body, byte[] header)
    {
        using var output = new MemoryStream();
        output.Write(header, 0, 4); output.WriteByte(0);
        output.Write(header, 4, 8); output.WriteByte(0);
        output.Write(Encoding.ASCII.GetBytes("POST\0/device/authenticate\0\0"));
        output.Write(Encoding.UTF8.GetBytes(body)); output.WriteByte(0);
        Assert(BinaryPrimitives.ReadUInt32BigEndian(header) == 1, "signature policy version");
        return output.ToArray();
    }

    private static ECDsa PublicKey(JsonElement proof) => ECDsa.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256,
        Q = new ECPoint { X = Decode(proof.GetProperty("x").GetString()!), Y = Decode(proof.GetProperty("y").GetString()!) }
    });
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "=");

    private sealed class ExposedRequest : XboxDeviceTokenRequest
    { internal JsonDocument Body(object proof) => JsonDocument.Parse(JsonSerializer.Serialize(BuildBody(proof))); }

    private sealed class FakeTickets : IDeviceRpsTicketProvider
    {
        private readonly Func<DeviceRpsTicketRequest, CancellationToken, Task<DeviceRpsTicket>> _acquire;
        internal FakeTickets(string value) : this((_, _) => Task.FromResult(new DeviceRpsTicket(ValidMetadata(value.Length), value))) { }
        internal FakeTickets(Func<DeviceRpsTicketRequest, CancellationToken, Task<DeviceRpsTicket>> acquire) => _acquire = acquire;
        internal int Calls { get; private set; }
        internal DeviceRpsTicketRequest? Request { get; private set; }
        public Task<DeviceRpsTicket> AcquireAsync(DeviceRpsTicketRequest request, CancellationToken cancellationToken)
        { Calls++; Request = request; return _acquire(request, cancellationToken); }
    }

    private sealed class SyntheticKey : IPopCryptoProvider, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public object ProofKey
        {
            get
            {
                var point = _key.ExportParameters(false).Q;
                return new { crv = "P-256", alg = "ES256", use = "sig", kty = "EC", x = Encode(point.X!), y = Encode(point.Y!) };
            }
        }
        internal byte[]? LastPayload { get; private set; }
        public byte[] Sign(byte[] data) { LastPayload = data.ToArray(); return _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        internal bool Verify(byte[] data, ReadOnlySpan<byte> signature) => _key.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        public void Dispose() => _key.Dispose();
    }

    private sealed class InvalidSigner(object proofKey) : IXboxRequestSigner
    {
        public object ProofKey => proofKey;
        public string SignRequest(string reqUri, string token, string body) => throw new Exception(Secret);
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;
        internal FakeHandler(string body, int status = 200) : this((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") })) { }
        internal FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) => _respond = respond;
        internal int Calls { get; private set; }
        internal string? Body { get; private set; }
        internal string? Signature { get; private set; }
        internal string? Url { get; private set; }
        internal string? Method { get; private set; }
        internal string? Authorization { get; private set; }
        internal string? Contract { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            Assert(request.RequestUri?.AbsoluteUri == DeviceRpsTokenProvider.Endpoint, "no unrelated endpoint allowed");
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Signature = request.Headers.GetValues("Signature").Single();
            Contract = request.Headers.GetValues("x-xbl-contract-version").Single();
            Url = request.RequestUri!.AbsoluteUri; Method = request.Method.Method; Authorization = request.Headers.Authorization?.ToString();
            return await _respond(request, cancellationToken);
        }
    }
}

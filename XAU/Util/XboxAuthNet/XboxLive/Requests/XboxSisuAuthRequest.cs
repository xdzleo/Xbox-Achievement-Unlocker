using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using System.Net.Http;
using XboxAuthNet.XboxLive.Responses;
using XboxAuthNet.XboxLive.Crypto;

namespace XboxAuthNet.XboxLive.Requests
{
    public enum XboxSisuProfile
    {
        OAuthCompatibility,
        NativeContextV2
    }

    public class XboxSisuAuthRequest : AbstractXboxSignedAuthRequest
    {
        // The existing OAuth caller has no native title/UCS context. Keep its
        // established contract instead of assuming native v2 is interchangeable.
        public XboxSisuProfile Profile { get; set; } = XboxSisuProfile.OAuthCompatibility;
        public string? TokenPrefix { get; set; } = XboxAuthConstants.XboxTokenPrefix;
        public string? AccessToken { get; set; }
        public string? RelyingParty { get; set; } = XboxAuthConstants.XboxLiveRelyingParty;
        public string? ClientId { get; set; }
        public string? DeviceToken { get; set; }
        public string? TitleId { get; set; }
        public string? SessionId { get; set; }
        public string? ClusterAffinity { get; private set; }
        public string? UcsCheckinToken { get; set; }
        public string? UcsWebToken { get; set; }
        public string[]? UserPrompts { get; set; }
        public bool RequestConsent { get; set; }
        public string? Sandbox { get; set; } = "RETAIL";

        protected override string ContractVersion => Profile switch
        {
            XboxSisuProfile.OAuthCompatibility => "1",
            XboxSisuProfile.NativeContextV2 => "2",
            _ => throw new InvalidOperationException("Unsupported SISU profile")
        };

        // Continuation is explicit and scoped to a single operation/account.
        // Missing headers clear older values instead of borrowing another session.
        public void ContinueFrom(XboxSisuContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            var affinity = context.ClusterAffinity;
            if (affinity != null)
                ValidateAffinity(affinity);
            SessionId = context.SessionId;
            ClusterAffinity = affinity;
        }

        protected override string RequestUrl => ClusterAffinity == null
            ? "https://sisu.xboxlive.com/authorize"
            : ValidateAffinity(ClusterAffinity).GetLeftPart(UriPartial.Authority) + "/authorize";

        private static Uri ValidateAffinity(string value)
        {
            // Local transport policy, not a recovered Windows validation rule.
            // A response header must not redirect signed OAuth material elsewhere.
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || uri.Scheme != Uri.UriSchemeHttps || uri.Port != 443
                || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
                || uri.AbsolutePath != "/"
                || !(uri.Host.Equals("sisu.xboxlive.com", StringComparison.OrdinalIgnoreCase)
                    || uri.Host.EndsWith(".sisu.xboxlive.com", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("Unsupported SISU cluster affinity endpoint");
            return uri;
        }
        protected override object BuildBody(object proofKey)
        { 
            if (string.IsNullOrEmpty(AccessToken))
                throw new InvalidOperationException("AccessToken was null");
            if (string.IsNullOrEmpty(RelyingParty))
                throw new InvalidOperationException("RelyingParty was null");

            string? wireTitleId = null;
            switch (Profile)
            {
                case XboxSisuProfile.OAuthCompatibility:
                    if (TitleId != null || SessionId != null || ClusterAffinity != null
                        || UcsCheckinToken != null || UcsWebToken != null
                        || UserPrompts != null || RequestConsent)
                        throw new InvalidOperationException("Native SISU fields require the explicit native profile");
                    break;
                case XboxSisuProfile.NativeContextV2:
                    // The observed native builder formats the configured uint64
                    // TitleId with %llu. An OAuth AppId is not a substitute.
                    if (!ulong.TryParse(TitleId, NumberStyles.None, CultureInfo.InvariantCulture, out var title))
                        throw new InvalidOperationException("Native SISU requires a decimal UInt64 TitleId");
                    wireTitleId = title.ToString(CultureInfo.InvariantCulture);
                    break;
                default:
                    throw new InvalidOperationException("Unsupported SISU profile");
            }

            var body = new Dictionary<string, object?>
            {
                ["AccessToken"] = TokenPrefix + AccessToken
            };
            // Insert only present fields: removing a dictionary entry and then
            // appending ProofKey can reuse its slot and change signed byte order.
            if (ClientId != null) body["AppId"] = ClientId;
            if (wireTitleId != null) body["TitleId"] = wireTitleId;
            if (DeviceToken != null) body["DeviceToken"] = DeviceToken;
            if (Sandbox != null) body["Sandbox"] = Sandbox;
            body["UseModernGamertag"] = true;
            body["SiteName"] = "user.auth.xboxlive.com";
            body["RelyingParty"] = RelyingParty;
            if (!string.IsNullOrEmpty(SessionId)) body["SessionId"] = SessionId;
            // FUN_1802a5960 gates the whole UCS group on both nonempty tokens.
            if (!string.IsNullOrEmpty(UcsCheckinToken) && !string.IsNullOrEmpty(UcsWebToken))
            {
                body["UcsCheckinToken"] = UcsCheckinToken;
                body["UcsWebToken"] = UcsWebToken;
                body["UserPrompts"] = UserPrompts ?? Array.Empty<string>();
                if (RequestConsent) body["Flow"] = "consent";
            }
            body["ProofKey"] = proofKey;
            return body;
        }

        public Task<XboxSisuResponse> Send(HttpClient httpClient, IXboxRequestSigner signer)
        {
            return Send<XboxSisuResponse>(httpClient, signer);
        }
    }
}

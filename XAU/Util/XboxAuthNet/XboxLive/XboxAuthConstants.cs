namespace XboxAuthNet.XboxLive
{
    public class XboxAuthConstants
    {
        public const string XboxScope = "service::user.auth.xboxlive.com::MBI_SSL";
        public const string XboxLiveRelyingParty = "http://xboxlive.com";
        // XboxPcApp's native GrtsAuthProvider carries the HTTPS Xbox Live
        // origin through its AuthManager initialization path. Keep it as a
        // separate candidate; changing the legacy default would alter every
        // existing XSTS caller.
        public const string XboxAppRelyingParty = "https://xboxlive.com";
        public const string XboxAuthRelyingParty = "http://auth.xboxlive.com";
        public const string XboxEventsRelyingParty = "http://events.xboxlive.com";
        public const string AzureTokenPrefix = "d=";
        public const string XboxTokenPrefix = "t=";
    }
}

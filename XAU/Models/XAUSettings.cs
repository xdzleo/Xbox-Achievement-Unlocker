public class XAUSettings
{
    public string? SettingsVersion { get; set; }
    public string? ToolVersion { get; set; }
    public bool UnlockAllEnabled { get; set; }
    public bool AutoSpooferEnabled { get; set; }
    public bool AutoLaunchXboxAppEnabled { get; set; }
    public bool LaunchHidden { get; set; }
    public bool FakeSignatureEnabled { get; set; }
    public bool RegionOverride { get; set; }
    public bool UseAcrylic { get; set; }
    public bool PrivacyMode { get; set; }
    public bool OAuthLogin { get; set; }
    public bool AutoGrabEventsToken { get; set; }
    // Experimental, off by default: ask SISU (contract 2) for the chosen title
    // before presence writes. Has no UI; set in settings.json or XAU_TITLE_BOUND_SISU=1.
    public bool TitleBoundSisuExperiment { get; set; }
    // Diagnostic, off by default: send the identical presence request matrix with
    // every token and log the responses. No UI; settings.json or XAU_PRESENCE_PROBE=1.
    public bool PresenceProbe { get; set; }
    public string? CachedEventsToken { get; set; }
    public DateTime? EventsTokenObtainedAt { get; set; }
    public string? EventsUserHash { get; set; }
}

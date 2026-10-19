#if !WINDOWS10_0_19041_0_OR_GREATER
#error The OnlineId backend must be compiled against the Windows SDK TFM.
#endif
using XboxAuthNet.Platforms.WindowsOnlineId;
using XboxAuthNet.XboxLive.DeviceRps;

// Compile-time interface assignment only. No instance is created and no WinRT API is invoked.
internal static class CompileContract
{
    internal static IDeviceRpsTicketProvider RequireContract(OnlineIdSystemTicketProvider provider) => provider;
}

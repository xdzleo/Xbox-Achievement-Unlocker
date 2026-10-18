using System.IO;
using XAU.ViewModels.Pages;

namespace XAU.Services;

// Headless test mode: XAU.exe --cli [options]
//
// It drives the app's own login (token read from the Xbox App process, or the
// saved OAuth session when OAuthLogin is on) and then runs the requested
// steps. It adds no credential handling of its own: it never reads, prints or
// accepts tokens, and never types credentials. Output goes to the normal
// events_debug.log as "CLI ..." lines, ending with "CLI done".
//
//   --cli                      enable the runner
//   --info <id[,id...]>        look up title names/devices (titlehub)
//   --probe <titleId>          run the presence probe matrix (forced on)
//   --title-bound              force the title-bound SISU experiment first
//   --sisu-title <id>          title id to ask SISU for (default: the probed game)
//   --native-device            device token with the native xgameruntime layout
//   --watch <seconds>          after the steps, log the presence read-back every 15 s
//   --pace <ms>                delay between probe steps (default 1500)
//   --stop                     DELETE presence and heartbeat when finished
//   --exit                     close the app when finished
//   --login-timeout <seconds>  wait for login (default 120)
public static class CliRunner
{
    public static bool Requested(string[] args) => args.Any(a => a.Equals("--cli", StringComparison.OrdinalIgnoreCase));

    public static void Start(string[] args)
    {
        // Set synchronously: the device token is built during login, which can start
        // before the background task below runs.
        HomeViewModel.ForceNativeDevice = Flag(args, "--native-device");
        _ = Task.Run(() => RunAsync(args));
    }

    private static string? Value(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }

    private static bool Flag(string[] args, string name) =>
        args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static async Task RunAsync(string[] args)
    {
        var exit = Flag(args, "--exit");
        try
        {
            var timeout = int.TryParse(Value(args, "--login-timeout"), out var t) && t > 0 ? t : 120;
            if (int.TryParse(Value(args, "--pace"), out var pace) && pace >= 0)
                HomeViewModel.ProbePaceMs = pace;
            HomeViewModel.ForceTitleBoundSisu = Flag(args, "--title-bound");
            var sisuTitle = Value(args, "--sisu-title");
            if (!string.IsNullOrWhiteSpace(sisuTitle))
                HomeViewModel.SisuTitleOverride = sisuTitle;
            var probeTitle = Value(args, "--probe");
            HomeViewModel.ForcePresenceProbe = !string.IsNullOrEmpty(probeTitle);

            HomeViewModel.EventsLog($"CLI start: probe={(probeTitle ?? "none")}; title_bound={HomeViewModel.ForceTitleBoundSisu}; pace_ms={HomeViewModel.ProbePaceMs}; oauth_login={HomeViewModel.Settings.OAuthLogin}");

            var deadline = DateTime.UtcNow.AddSeconds(timeout);
            var triedLogin = false;
            var loginKickoff = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline)
            {
                if (HomeViewModel._isLoggedIn && !string.IsNullOrEmpty(HomeViewModel.XUIDOnly)
                    && !string.IsNullOrWhiteSpace(HomeViewModel.XAUTH))
                    break;
                if (!triedLogin && HomeViewModel.Settings.OAuthLogin && DateTime.UtcNow > loginKickoff
                    && HomeViewModel.Instance != null)
                {
                    triedLogin = true;
                    HomeViewModel.EventsLog("CLI: starting the saved-session OAuth login");
                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => HomeViewModel.Instance.CliOAuthLogin());
                }
                await Task.Delay(500);
            }
            if (!HomeViewModel._isLoggedIn || string.IsNullOrEmpty(HomeViewModel.XUIDOnly))
            {
                HomeViewModel.EventsLog("CLI error: not logged in within the timeout (an interactive login is needed; the CLI does not enter credentials)");
                return;
            }
            // Let the presence token finish building after the profile token.
            await Task.Delay(4000);

            var infoIds = Value(args, "--info");
            if (!string.IsNullOrEmpty(infoIds))
            {
                var api = new XboxRestAPI(HomeViewModel.XAUTH);
                foreach (var id in infoIds.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    try
                    {
                        var info = await api.GetGameTitleAsync(HomeViewModel.XUIDOnly, id);
                        var title = info?.Titles.FirstOrDefault();
                        HomeViewModel.EventsLog(title == null
                            ? $"CLI info {id}: not found"
                            : $"CLI info {id}: name='{Safe(title.Name)}'; type={Safe(title.Type)}; devices={string.Join(",", title.Devices.Select(Safe))}");
                    }
                    catch (Exception ex)
                    {
                        HomeViewModel.EventsLog($"CLI info {id}: failed ({ex.GetType().Name})");
                    }
                }
            }

            if (!string.IsNullOrEmpty(probeTitle))
            {
                if (HomeViewModel.PrepareTitleBoundPresence != null)
                    await HomeViewModel.PrepareTitleBoundPresence(probeTitle);
                else if (HomeViewModel.ForceTitleBoundSisu)
                    HomeViewModel.EventsLog("CLI: title-bound SISU needs an OAuth login; skipped");
                await HomeViewModel.RunPresenceProbeAsync(probeTitle);
            }

            if (int.TryParse(Value(args, "--watch"), out var watchSeconds) && watchSeconds > 0)
            {
                var watchApi = new XboxRestAPI(HomeViewModel.XAUTH);
                for (var waited = 0; waited < watchSeconds; waited += 15)
                {
                    await Task.Delay(15000);
                    HomeViewModel.EventsLog($"CLI watch +{waited + 15}s: {await watchApi.ReadbackDescriptionAsync(HomeViewModel.XUIDOnly)}");
                }
            }

            if (Flag(args, "--stop"))
            {
                await new XboxRestAPI(HomeViewModel.PresenceXAUTH, presenceSigner: HomeViewModel.PresenceSigner)
                    .DeletePresenceAsync(HomeViewModel.XUIDOnly);
                await new XboxRestAPI(HomeViewModel.XAUTH).StopHeartbeatAsync(HomeViewModel.XUIDOnly);
                HomeViewModel.EventsLog("CLI: presence and heartbeat DELETE sent");
            }
        }
        catch (Exception ex)
        {
            HomeViewModel.EventsLog($"CLI error: {ex.GetType().Name}");
        }
        finally
        {
            HomeViewModel.EventsLog("CLI done");
            if (exit)
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => System.Windows.Application.Current.Shutdown());
        }
    }

    private static string Safe(string? value) =>
        string.IsNullOrEmpty(value) ? "-" : new string(value.Where(c => !char.IsControl(c)).Take(60).ToArray());
}

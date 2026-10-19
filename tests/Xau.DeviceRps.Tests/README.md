# Offline DeviceRPS contracts

Run `dotnet run --project tests/Xau.DeviceRps.Tests/Xau.DeviceRps.Tests.csproj`.
All acquisitions and HTTP exchanges are fake. Keys, tickets and tokens are synthetic.
The tests check the explicit RPS wire branch, acquisition gates, exact-body signing with a
matching public JWK, response/lifetime gates, safe diagnostics, cancellation and isolation.
The existing `Xau.Auth.Tests` program is unchanged.

Build `tests/Xau.DeviceRps.Windows.Compile/Xau.DeviceRps.Windows.Compile.csproj` separately
to compile the concrete public OnlineId backend against Windows SDK 19041. It is a library
with no entry point and does not create a provider or acquire a ticket.
`WINDOWS10_0_19041_0_OR_GREATER` guards the backend in older/non-SDK targets.

DeviceRPS is opt-in. The app must pass its own ApplicationId and retain the same signer
for any later token operations. An ApplicationId and a successful device exchange do not
establish OAuth user/account binding, title authorization, SISU/XSTS validity or presence.
Use the owned `DeviceRpsTokenProvider.CreateHttpClient()` transport for real exchanges;
an injected HttpClient must also disable redirects. No fallback to OAuth tickets or PoP occurs.

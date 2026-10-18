# Offline XboxAuthNet contract tests

This project links the request, response, and exception classes used by XAU directly from `XAU/Util/XboxAuthNet`. It never calls Xbox services and uses a local `HttpMessageHandler` to capture the request.

Run in CI or a machine with the .NET 9 SDK:

```powershell
dotnet run --project tests/Xau.Auth.Tests -c Release
```

The suite checks the signed and unsigned XSTS JSON contracts, relying-party defaults, User/Device/Title token propagation, ProofKey serialization, exact-body signing, common headers, and numeric/header `X-Err` conversion. Synthetic values only; no account tokens are stored.

#if WINDOWS10_0_19041_0_OR_GREATER
using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.Security.Authentication.OnlineId;
using XboxAuthNet.XboxLive.DeviceRps;

namespace XboxAuthNet.Platforms.WindowsOnlineId;

/// <summary>
/// Public WinRT backend. Requires a Windows SDK TFM such as net9.0-windows10.0.19041.0.
/// ApplicationId is supplied by the caller and must belong to that application.
/// No package/title identity, user token, account store or other process is inspected.
/// </summary>
public sealed class OnlineIdSystemTicketProvider : IDeviceRpsTicketProvider
{
    // Default is mutable. Serialize our own ApplicationId assignment and acquisition across instances.
    private static readonly SemaphoreSlim AcquisitionGate = new SemaphoreSlim(1, 1);

    public async Task<DeviceRpsTicket> AcquireAsync(DeviceRpsTicketRequest request,
        CancellationToken cancellationToken)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        await AcquisitionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var authenticator = OnlineIdSystemAuthenticator.Default;
            authenticator.ApplicationId = request.ApplicationId;
            // Exactly the public one-string constructor. Windows owns scope/policy conversion.
            var serviceRequest = new OnlineIdServiceTicketRequest(DeviceRpsTicketRequest.Service);
            var result = await authenticator.GetTicketAsync(serviceRequest).AsTask(cancellationToken)
                .ConfigureAwait(false);
            if (result == null)
                return new DeviceRpsTicket(new DeviceRpsAcquisitionMetadata(false, null, null,
                    false, false, null, 0), null);
            var status = (int)result.Status;
            var extendedError = result.ExtendedError?.HResult;
            if (status != 0 || (extendedError ?? 0) < 0)
                return new DeviceRpsTicket(new DeviceRpsAcquisitionMetadata(true, status, extendedError,
                    false, false, null, 0), null);
            var identity = result.Identity;
            var ticket = identity?.Ticket;
            var ticketError = ticket?.ErrorCode;
            var value = ticket != null && ticketError == 0 ? ticket.Value : null;
            return new DeviceRpsTicket(new DeviceRpsAcquisitionMetadata(true, status, extendedError,
                identity != null, ticket != null, ticketError, value?.Length ?? 0), value);
        }
        finally { AcquisitionGate.Release(); }
    }
}
#endif

using System;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace XboxAuthNet.XboxLive.DeviceRps;

/// <summary>Public OnlineId system-ticket acquisition. No user/OAuth or stored-token fallback.</summary>
public interface IDeviceRpsTicketProvider
{
    Task<DeviceRpsTicket> AcquireAsync(DeviceRpsTicketRequest request, CancellationToken cancellationToken);
}

/// <summary>The application must supply its own GUID. A GUID is context, not Xbox authorization.</summary>
public sealed class DeviceRpsTicketRequest
{
    public const string Service = "service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";

    public DeviceRpsTicketRequest(Guid applicationId)
    {
        if (applicationId == Guid.Empty)
            throw new ArgumentException("An application-owned ApplicationId is required", nameof(applicationId));
        ApplicationId = applicationId;
    }

    public Guid ApplicationId { get; }
}

/// <summary>Only nonsecret acquisition diagnostics. Status 0 is OnlineId success.</summary>
public sealed class DeviceRpsAcquisitionMetadata
{
    public DeviceRpsAcquisitionMetadata(bool resultPresent, int? status, int? extendedError,
        bool identityPresent, bool ticketPresent, int? ticketError, int ticketUtf16Length)
    {
        if (ticketUtf16Length < 0) throw new ArgumentOutOfRangeException(nameof(ticketUtf16Length));
        ResultPresent = resultPresent;
        Status = status;
        ExtendedError = extendedError;
        IdentityPresent = identityPresent;
        TicketPresent = ticketPresent;
        TicketError = ticketError;
        TicketUtf16Length = ticketUtf16Length;
    }

    public bool ResultPresent { get; }
    public int? Status { get; }
    public int? ExtendedError { get; }
    public bool IdentityPresent { get; }
    public bool TicketPresent { get; }
    public int? TicketError { get; }
    public int TicketUtf16Length { get; }
    // Intentionally stricter than the native warning-only Ticket.ErrorCode branch.
    public bool Accepted => ResultPresent && Status == 0 && (ExtendedError ?? 0) >= 0
        && IdentityPresent && TicketPresent && TicketError == 0 && TicketUtf16Length > 0;
}

/// <summary>Operation-local secret. Do not log, serialize, persist, or reinterpret Value.</summary>
public sealed class DeviceRpsTicket
{
    public DeviceRpsTicket(DeviceRpsAcquisitionMetadata metadata, string? value)
    {
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        Value = value;
    }

    public DeviceRpsAcquisitionMetadata Metadata { get; }
    [JsonIgnore, System.Runtime.Serialization.IgnoreDataMember]
    public string? Value { get; }
    public override string ToString() => "DeviceRpsTicket (credential redacted)";
}

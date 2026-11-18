using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using JustCryptDns.Core.Configuration;

namespace JustCryptDns.Core.Ipc;

public static class IpcConstants
{
    public const string DefaultPipeName = "JustCryptDns.Ipc.v1";
    public const int ProtocolVersion = 1;
    public const int MaxMessageBytes = 256 * 1024;
}

[JsonConverter(typeof(JsonStringEnumConverter<DnsEngineState>))]
public enum DnsEngineState
{
    NotImplemented,
    Stopped,
    Starting,
    Running,
    Degraded,
    Stopping,
}

[JsonConverter(typeof(JsonStringEnumConverter<IpcRequestKind>))]
public enum IpcRequestKind
{
    GetStatus,
    SetEngineEnabled,
    RestartEngine,
    ReloadConfiguration,
    SetGamingMode,
    RestoreOriginalDns,
}

public sealed record IpcRequest(
    IpcRequestKind Kind,
    bool? BoolValue = null,
    string? StringValue = null,
    int ProtocolVersion = IpcConstants.ProtocolVersion);

public sealed record ServiceStatusSnapshot
{
    public required string ServiceVersion { get; init; }

    public required DateTimeOffset StartedAt { get; init; }

    public required DnsEngineState EngineState { get; init; }

    public bool IsEngineImplemented { get; init; }

    public bool IsEngineEnabled { get; init; }

    public bool IsGamingModeEnabled { get; init; }

    public string? ActiveResolverId { get; init; }

    public string? ActiveResolverName { get; init; }

    public string? ActiveProtocol { get; init; }

    public string? ListenEndpoint { get; init; }

    public long TotalQueries { get; init; }

    public double? LastLatencyMs { get; init; }

    public bool HasAdapterBackup { get; init; }

    public string? LastError { get; init; }
}

public sealed record IpcResponse(
    bool Success,
    ServiceStatusSnapshot Status,
    string? ErrorCode = null,
    string? Message = null,
    int ProtocolVersion = IpcConstants.ProtocolVersion);

[JsonConverter(typeof(JsonStringEnumConverter<ServiceConnectionState>))]
public enum ServiceConnectionState
{
    Unknown,
    Connected,
    ServiceNotRunning,
    AccessDenied,
    Error,
}

public interface IServiceIpcHandler
{
    Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken cancellationToken = default);
}

public interface IServiceClient
{
    ServiceConnectionState ConnectionState { get; }

    ServiceStatusSnapshot? LastStatus { get; }

    event EventHandler? StateChanged;

    Task<IpcResponse?> SendAsync(IpcRequest request, CancellationToken cancellationToken = default);

    Task<ServiceStatusSnapshot?> RefreshStatusAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Length-prefixed (4-byte little-endian) UTF-8 JSON framing over any <see cref="Stream"/>.
/// Enforces <see cref="IpcConstants.MaxMessageBytes"/> to reject malformed or oversized frames.
/// </summary>
public static class IpcFraming
{
    public static async Task WriteMessageAsync<T>(Stream stream, T value, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, SettingsJson.Options);
        if (payload.Length == 0 || payload.Length > IpcConstants.MaxMessageBytes)
        {
            throw new InvalidDataException($"IPC frame size {payload.Length} is out of bounds.");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<T?> ReadMessageAsync<T>(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[4];
        var read = await ReadExactlyOrEofAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return default;
        }

        if (read < 4)
        {
            throw new EndOfStreamException("Truncated IPC frame header.");
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > IpcConstants.MaxMessageBytes)
        {
            throw new InvalidDataException($"Invalid IPC frame length {length}.");
        }

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(payload, SettingsJson.Options)
            ?? throw new InvalidDataException("IPC frame deserialized to null.");
    }

    private static async Task<int> ReadExactlyOrEofAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                return total;
            }

            total += n;
        }

        return total;
    }
}

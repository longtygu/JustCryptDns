using System.Net;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Proxy;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

/// <summary>
/// Unified <see cref="IDnsEngine"/> adapter that routes lifecycle and probe commands to the
/// elevated <c>JustCryptDnsService</c> via named-pipe IPC when connected, and transparently
/// falls back to the in-process <see cref="DnsEngineService"/> in standalone/portable mode.
/// </summary>
public sealed class HybridDnsEngineProxy : IDnsEngine
{
    private readonly DnsEngineService _local;
    private readonly IServiceClient _serviceClient;
    private readonly ISettingsService _settings;
    private readonly ILogger<HybridDnsEngineProxy> _logger;

    private DnsEngineRuntimeStats? _cachedServiceStats;
    private int _disposed;

    public HybridDnsEngineProxy(
        DnsEngineService local,
        IServiceClient serviceClient,
        ISettingsService settings,
        ILogger<HybridDnsEngineProxy> logger)
    {
        _local = local;
        _serviceClient = serviceClient;
        _settings = settings;
        _logger = logger;

        _local.StateChanged += OnLocalStateChanged;
        _serviceClient.StateChanged += OnServiceClientStateChanged;
    }

    public bool IsDelegatingToService => _serviceClient.ConnectionState == ServiceConnectionState.Connected;

    public event EventHandler<DnsEngineRuntimeStats>? StateChanged;

    public DnsEngineRuntimeStats GetStats()
    {
        if (!IsDelegatingToService)
        {
            return _local.GetStats();
        }

        return Volatile.Read(ref _cachedServiceStats)
            ?? BuildFallbackStatsFromSnapshot(_serviceClient.LastStatus, _local.GetStats());
    }

    public async Task<DnsEngineRuntimeStats?> RefreshFromServiceAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return null;
        }

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.GetEngineDetailedStats), cancellationToken)
            .ConfigureAwait(false);
        if (response is null)
        {
            return null;
        }

        DnsEngineRuntimeStats? parsed = null;
        if (!string.IsNullOrWhiteSpace(response.Message))
        {
            try
            {
                parsed = JsonSerializer.Deserialize<DnsEngineRuntimeStats>(response.Message, SettingsJson.Options);
            }
            catch (JsonException ex)
            {
                _logger.LogDebug(ex, "Could not deserialize detailed DNS engine stats from service.");
            }
        }

        var resolved = parsed ?? BuildFallbackStatsFromSnapshot(response.Status, _local.GetStats());
        var previous = Interlocked.Exchange(ref _cachedServiceStats, resolved);
        if (!Equals(previous, resolved))
        {
            StateChanged?.Invoke(this, resolved);
        }

        return resolved;
    }

    private async Task<bool> EnsureServiceConnectionFreshAsync(CancellationToken cancellationToken)
    {
        if (IsDelegatingToService)
        {
            return true;
        }

        try
        {
            await _serviceClient.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Pre-command service reconnect probe did not connect.");
        }

        return IsDelegatingToService;
    }

    public async Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default)
    {
        if (!await EnsureServiceConnectionFreshAsync(cancellationToken).ConfigureAwait(false))
        {
            return await _local.StartAsync(cancellationToken).ConfigureAwait(false);
        }

        await _settings.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration), cancellationToken)
            .ConfigureAwait(false);

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.SetEngineEnabled, BoolValue: true), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (!await EnsureServiceConnectionFreshAsync(cancellationToken).ConfigureAwait(false))
        {
            await _local.StopAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.SetEngineEnabled, BoolValue: false), cancellationToken)
            .ConfigureAwait(false);
        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default)
    {
        if (!await EnsureServiceConnectionFreshAsync(cancellationToken).ConfigureAwait(false))
        {
            return await _local.RestartAsync(cancellationToken).ConfigureAwait(false);
        }

        await _settings.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration), cancellationToken)
            .ConfigureAwait(false);

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.RestartEngine), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    public async Task<(bool Success, string? Error)> SwitchResolverAsync(
        string resolverId,
        CancellationToken cancellationToken = default)
    {
        if (!await EnsureServiceConnectionFreshAsync(cancellationToken).ConfigureAwait(false))
        {
            return await _local.SwitchResolverAsync(resolverId, cancellationToken).ConfigureAwait(false);
        }

        await _settings.FlushAsync(cancellationToken).ConfigureAwait(false);
        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration, StringValue: resolverId), cancellationToken)
            .ConfigureAwait(false);

        if (response is { Success: true })
        {
            await _settings.ReloadFromDiskAsync(cancellationToken).ConfigureAwait(false);
        }

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    public async Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return await _local.ProbeActiveResolverAsync(cancellationToken).ConfigureAwait(false);
        }

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ProbeActiveResolver), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        if (response is { Message: not null })
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<DnsQueryResult>(response.Message, SettingsJson.Options);
                if (parsed is not null)
                {
                    return parsed;
                }
            }
            catch (JsonException ex)
            {
                _logger.LogDebug(ex, "Could not deserialize probe result from service.");
            }
        }

        var current = GetStats();
        return new DnsQueryResult(
            response?.Success == true,
            [],
            current.LastLatencyMs ?? 0,
            current.ActiveResolverId,
            current.ActiveProtocol,
            response?.Message ?? (response is null ? "Background service did not respond." : null));
    }

    public async Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(
        CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return await _local.TestLocalProxyAsync(cancellationToken).ConfigureAwait(false);
        }

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.TestLocalProxy), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        if (response is { Message: not null })
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<LocalProxyTestResult>(response.Message, SettingsJson.Options);
                if (parsed is not null)
                {
                    return (parsed.Success, parsed.LatencyMs, parsed.Summary);
                }
            }
            catch (JsonException ex)
            {
                _logger.LogDebug(ex, "Could not deserialize local proxy test result from service.");
            }
        }

        return response is null
            ? (false, 0, "Background service did not respond.")
            : (response.Success, 0, response.Message ?? "Completed.");
    }

    public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        bool includeIpv6 = false,
        CancellationToken cancellationToken = default) =>
        _local.ResolveHostAsync(host, includeIpv6, cancellationToken);

    public async Task<(bool Success, string? Error)> PauseForCaptivePortalAsync(
        TimeSpan duration,
        CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return await _local.PauseForCaptivePortalAsync(duration, cancellationToken).ConfigureAwait(false);
        }

        var seconds = ((int)Math.Max(30, duration.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.PauseCaptivePortal, StringValue: seconds), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    public async Task<(bool Success, string? Error)> ResumeFromCaptivePortalAsync(
        CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return await _local.ResumeFromCaptivePortalAsync(cancellationToken).ConfigureAwait(false);
        }

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ResumeCaptivePortal), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    /// <summary>Stops only the in-process fallback engine if it was somehow started.</summary>
    public async Task StopLocalFallbackOnlyAsync(CancellationToken cancellationToken = default)
    {
        if (_local.GetStats().State != DnsEngineState.Stopped)
        {
            await _local.StopAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _local.StateChanged -= OnLocalStateChanged;
        _serviceClient.StateChanged -= OnServiceClientStateChanged;
        await _local.DisposeAsync().ConfigureAwait(false);
    }

    private void OnLocalStateChanged(object? sender, DnsEngineRuntimeStats stats)
    {
        if (!IsDelegatingToService)
        {
            StateChanged?.Invoke(this, stats);
        }
    }

    private void OnServiceClientStateChanged(object? sender, EventArgs e)
    {
        if (!IsDelegatingToService)
        {
            Volatile.Write(ref _cachedServiceStats, null);
        }

        StateChanged?.Invoke(this, GetStats());
    }

    private static DnsEngineRuntimeStats BuildFallbackStatsFromSnapshot(
        ServiceStatusSnapshot? snap,
        DnsEngineRuntimeStats localFallback)
    {
        if (snap is null)
        {
            return localFallback;
        }

        var proto = Enum.TryParse<DnsProtocol>(snap.ActiveProtocol, ignoreCase: true, out var parsed)
            ? parsed
            : localFallback.ActiveProtocol;

        return localFallback with
        {
            State = snap.EngineState,
            ActiveResolverId = snap.ActiveResolverId ?? localFallback.ActiveResolverId,
            ActiveResolverName = snap.ActiveResolverName ?? localFallback.ActiveResolverName,
            ActiveProtocol = proto,
            ListenEndpoint = snap.ListenEndpoint ?? localFallback.ListenEndpoint,
            TotalQueries = snap.TotalQueries,
            BlockedQueries = snap.BlockedQueries,
            CacheHits = snap.CacheHits,
            CacheHitRatioPercent = snap.CacheHitRatioPercent,
            RewrittenQueries = snap.RewrittenQueries,
            StaleCacheHits = snap.StaleCacheHits,
            PrefetchCount = snap.PrefetchCount,
            LastLatencyMs = snap.LastLatencyMs,
            HasAdapterBackup = snap.HasAdapterBackup,
            ActiveVpnAdapterName = snap.ActiveVpnAdapterName,
            IsCaptivePortalPaused = snap.IsCaptivePortalPaused,
            LastError = snap.LastError,
        };
    }
}

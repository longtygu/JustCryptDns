using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

public sealed record OperationModeState(
    AppOperationMode SelectedMode,
    AppOperationMode EffectiveMode,
    AutoModeReason AutoReason,
    string? AutoDetail,
    bool MinimizeVisualEffects,
    bool IsApplying);

public interface IOperationModeService : IDisposable
{
    OperationModeState CurrentState { get; }

    event EventHandler<OperationModeState>? StateChanged;

    void Start();

    Task SetModeAsync(AppOperationMode mode, CancellationToken cancellationToken = default);

    OperationModeProfile GetProfileCopy(AppOperationMode mode);

    AutoModeRulesSettings GetAutoRulesCopy();

    Task UpdateModeProfileAsync(AppOperationMode mode, OperationModeProfile updatedProfile, CancellationToken cancellationToken = default);

    Task UpdateAutoRulesAsync(AutoModeRulesSettings updatedRules, CancellationToken cancellationToken = default);

    Task ResetModeToDefaultAsync(AppOperationMode mode, CancellationToken cancellationToken = default);
}

/// <summary>
/// Orchestrates the 5 seamless operating modes (HighSpeed, Gaming, Balanced, Auto, Security),
/// manages baseline snapshot restoration, per-mode customization, lightweight Win32 Auto-mode probing,
/// and live synchronization with local engines and the Windows Service.
/// </summary>
public sealed class OperationModeService : IOperationModeService
{
    private readonly ISettingsService _settings;
    private readonly IDnsEngine _dnsEngine;
    private readonly IResolverLibraryService _resolverLibrary;
    private readonly IDnsFilteringService? _filtering;
    private readonly IGamingEngineService? _gamingEngine;
    private readonly IFirewallBlocklistCoordinator? _firewallCoordinator;
    private readonly INetworkDiagnosticsService? _diagnostics;
    private readonly IThreatIntelligenceService? _threatIntel;
    private readonly IConnectionMonitorService? _connectionMonitor;
    private readonly IServiceClient? _serviceClient;
    private readonly ILogger<OperationModeService> _logger;
    private readonly OperationModeEvaluator _evaluator = new();
    private readonly SemaphoreSlim _applyGate = new(1, 1);

    private Timer? _autoTimer;
    private int _autoTickInFlight;
    private uint _lastFgPid;
    private string? _lastFgProcessName;
    private bool _disposed;
    private OperationModeState _state;

    public OperationModeService(
        ISettingsService settings,
        IDnsEngine dnsEngine,
        IResolverLibraryService resolverLibrary,
        ILogger<OperationModeService> logger,
        IDnsFilteringService? filtering = null,
        IGamingEngineService? gamingEngine = null,
        IFirewallBlocklistCoordinator? firewallCoordinator = null,
        INetworkDiagnosticsService? diagnostics = null,
        IThreatIntelligenceService? threatIntel = null,
        IConnectionMonitorService? connectionMonitor = null,
        IServiceClient? serviceClient = null)
    {
        _settings = settings;
        _dnsEngine = dnsEngine;
        _resolverLibrary = resolverLibrary;
        _logger = logger;
        _filtering = filtering;
        _gamingEngine = gamingEngine;
        _firewallCoordinator = firewallCoordinator;
        _diagnostics = diagnostics;
        _threatIntel = threatIntel;
        _connectionMonitor = connectionMonitor;
        _serviceClient = serviceClient;

        var selected = _settings.Current.OperationMode.ActiveMode;
        var effective = selected == AppOperationMode.Auto ? AppOperationMode.Balanced : selected;
        var profile = _settings.Current.OperationMode.GetProfile(effective);
        _state = new OperationModeState(
            selected,
            effective,
            AutoModeReason.Normal,
            null,
            profile.MinimizeVisualEffects,
            IsApplying: false);
    }

    public OperationModeState CurrentState => _state;

    public event EventHandler<OperationModeState>? StateChanged;

    public void Start()
    {
        if (_disposed)
        {
            return;
        }

        if (_settings.Current.OperationMode.ActiveMode == AppOperationMode.Auto)
        {
            StartAutoMonitor();
        }
    }

    public OperationModeProfile GetProfileCopy(AppOperationMode mode) =>
        _settings.Current.OperationMode.GetProfile(mode).Clone();

    public AutoModeRulesSettings GetAutoRulesCopy() =>
        _settings.Current.OperationMode.AutoRules.Clone();

    public async Task SetModeAsync(AppOperationMode mode, CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return;
        }

        if (mode == AppOperationMode.Auto)
        {
            _evaluator.Reset(AppOperationMode.Balanced);
            var signals = await CollectAutoSignalsAsync(cancellationToken).ConfigureAwait(false);
            var decision = _evaluator.Evaluate(signals, _settings.Current.OperationMode.AutoRules, DateTimeOffset.UtcNow);
            await ApplyEffectiveModeAsync(
                AppOperationMode.Auto,
                decision.EffectiveMode,
                decision.Reason,
                decision.Detail,
                cancellationToken).ConfigureAwait(false);
            StartAutoMonitor();
            return;
        }

        StopAutoMonitor();
        await ApplyEffectiveModeAsync(
            mode,
            mode,
            AutoModeReason.Normal,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateModeProfileAsync(
        AppOperationMode mode,
        OperationModeProfile updatedProfile,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(updatedProfile);
        if (_disposed || mode == AppOperationMode.Auto)
        {
            return;
        }

        var copy = updatedProfile.Clone();
        await _settings.UpdateAsync(s =>
        {
            s.OperationMode.ModeProfiles[mode] = copy;
        }, cancellationToken).ConfigureAwait(false);

        var current = _state;
        if (current.EffectiveMode == mode)
        {
            await ApplyEffectiveModeAsync(
                current.SelectedMode,
                current.EffectiveMode,
                current.AutoReason,
                current.AutoDetail,
                cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task UpdateAutoRulesAsync(AutoModeRulesSettings updatedRules, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(updatedRules);
        if (_disposed)
        {
            return;
        }

        var copy = updatedRules.Clone();
        await _settings.UpdateAsync(s =>
        {
            s.OperationMode.AutoRules = copy;
        }, cancellationToken).ConfigureAwait(false);

        if (_state.SelectedMode == AppOperationMode.Auto)
        {
            var signals = await CollectAutoSignalsAsync(cancellationToken).ConfigureAwait(false);
            var decision = _evaluator.Evaluate(signals, _settings.Current.OperationMode.AutoRules, DateTimeOffset.UtcNow);
            if (decision.Changed)
            {
                await ApplyEffectiveModeAsync(
                    AppOperationMode.Auto,
                    decision.EffectiveMode,
                    decision.Reason,
                    decision.Detail,
                    cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public async Task ResetModeToDefaultAsync(AppOperationMode mode, CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return;
        }

        await _settings.UpdateAsync(s => s.OperationMode.ResetModeToDefault(mode), cancellationToken).ConfigureAwait(false);

        var current = _state;
        if (mode == AppOperationMode.Auto && current.SelectedMode == AppOperationMode.Auto)
        {
            await SetModeAsync(AppOperationMode.Auto, cancellationToken).ConfigureAwait(false);
        }
        else if (current.EffectiveMode == mode)
        {
            await ApplyEffectiveModeAsync(
                current.SelectedMode,
                current.EffectiveMode,
                current.AutoReason,
                current.AutoDetail,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ApplyEffectiveModeAsync(
        AppOperationMode selectedMode,
        AppOperationMode effectiveMode,
        AutoModeReason autoReason,
        string? autoDetail,
        CancellationToken cancellationToken)
    {
        await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var profile = _settings.Current.OperationMode.GetProfile(effectiveMode).Clone();
            PublishState(_state with { SelectedMode = selectedMode, IsApplying = true });

            var before = _settings.Current;
            var prevLeakGuard = before.Connections.EnableDnsLeakGuard;
            var prevFilteringEnabled = before.Filtering.IsFilteringEnabled;
            var prevGamingEnabled = _gamingEngine?.IsGamingModeEnabled ?? before.Gaming.IsGamingModeEnabled;
            var prevResolverId = before.Dns.ActiveResolverId;
            var prevSecondaryId = before.Dns.SecondaryResolverId;
            var prevBlocklistFlags = (before.Filtering.Blocklists ?? [])
                .Where(b => b.IsBuiltIn)
                .Select(b => (b.Id, b.IsEnabled))
                .ToList();

            var validPrimary = ResolveValidResolverId(profile.ResolverId, BuiltInResolvers.DefaultResolverId);
            var validSecondary = ResolveValidResolverId(profile.SecondaryResolverId, BuiltInResolvers.DefaultSecondaryResolverId);

            await _settings.UpdateAsync(s =>
            {
                // Capture pre-mode baseline once so user appearance & default blocklists can be restored cleanly.
                s.OperationMode.BaselineSnapshot ??= OperationBaselineSnapshot.CaptureFrom(s);
                var baseline = s.OperationMode.BaselineSnapshot;

                s.OperationMode.ActiveMode = selectedMode;

                // DNS & Resolver
                s.Dns.ActiveResolverId = validPrimary;
                s.Dns.SecondaryResolverId = validSecondary;
                s.Dns.QueryTimeoutMs = profile.QueryTimeoutMs;
                s.Dns.BlockFirefoxDohCanary = profile.BlockFirefoxDohCanary;

                // Cache
                s.Cache.IsCacheEnabled = true;
                s.Cache.MaxEntries = profile.CacheMaxEntries;
                s.Cache.EnablePrefetch = profile.EnableCachePrefetch;
                s.Cache.EnableServeStale = profile.EnableServeStale;

                // Resilience / Encryption enforcement
                s.Resilience.Policy = profile.ForceEncryptedOnly
                    ? FailoverPolicy.EncryptedOnly
                    : FailoverPolicy.EncryptedThenPlainFallback;

                // Filtering (strictly preserves CustomBlockedDomains, Allowlist, and custom blocklists)
                s.Filtering.IsFilteringEnabled = profile.EnableFiltering;
                if (s.Filtering.Blocklists is { Count: > 0 } lists)
                {
                    var baselineEnabledSet = baseline.EnabledBuiltInBlocklistIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
                    for (var i = 0; i < lists.Count; i++)
                    {
                        var item = lists[i];
                        if (!item.IsBuiltIn)
                        {
                            continue;
                        }

                        var desiredEnabled = profile.EnableAllBuiltInBlocklists
                            ? true
                            : (baselineEnabledSet.Count > 0 ? baselineEnabledSet.Contains(item.Id) : item.IsEnabled);
                        if (item.IsEnabled != desiredEnabled)
                        {
                            lists[i] = item with { IsEnabled = desiredEnabled };
                        }
                    }
                }

                // Security / Connections (strictly preserves BlockedRules and BlockedApps)
                s.Connections.EnableDnsLeakGuard = profile.EnableDnsLeakGuard;
                s.Connections.EnableThreatIntelligence = profile.EnableThreatIntelligence;
                s.Connections.AutoBlockDetectedThreats = profile.AutoBlockDetectedThreats;
                s.Connections.VerifyProcessSignatures = profile.VerifyProcessSignatures;

                // Monitoring & Visual Performance
                s.Performance.MonitoringMode = profile.MonitoringMode;
                if (profile.MinimizeVisualEffects)
                {
                    s.Appearance.Animations = AnimationLevel.Off;
                    s.Appearance.TransparencyEnabled = false;
                    s.Appearance.StatusPulseStyle = StatusPulseStyle.Off;
                }
                else
                {
                    s.Appearance.Animations = baseline.Animations;
                    s.Appearance.TransparencyEnabled = baseline.TransparencyEnabled;
                    s.Appearance.Transparency = baseline.Transparency;
                    s.Appearance.StatusPulseStyle = baseline.StatusPulseStyle;
                }
            }, cancellationToken).ConfigureAwait(false);

            // Apply live subsystem updates
            if (_gamingEngine is not null && prevGamingEnabled != profile.EnableGamingEngine)
            {
                try
                {
                    await _gamingEngine.SetGamingModeAsync(profile.EnableGamingEngine, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Gaming engine mode toggle failed softly during mode switch.");
                }
            }

            var blocklistsChanged = (_settings.Current.Filtering.Blocklists ?? [])
                .Where(b => b.IsBuiltIn)
                .Zip(prevBlocklistFlags, (curr, prev) => curr.IsEnabled != prev.IsEnabled)
                .Any(changed => changed);

            if (_filtering is not null && (prevFilteringEnabled != profile.EnableFiltering || blocklistsChanged))
            {
                try
                {
                    _filtering.ReloadBlocklistsFromDisk();
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Filtering reload failed softly during mode switch.");
                }
            }

            var engineState = _dnsEngine.GetStats().State;
            if (engineState is DnsEngineState.Running or DnsEngineState.Degraded
                && (!string.Equals(prevResolverId, validPrimary, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(prevSecondaryId, validSecondary, StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    await _dnsEngine.SwitchResolverAsync(validPrimary, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "DNS engine resolver switch failed softly during mode switch.");
                }
            }

            if (_firewallCoordinator is not null && prevLeakGuard != profile.EnableDnsLeakGuard)
            {
                try
                {
                    var conn = _settings.Current.Connections;
                    await _firewallCoordinator.SyncSecurityAsync(
                        new FirewallSyncRequestPayload(
                            conn.BlockedRules,
                            conn.BlockedApps,
                            EnableDnsLeakGuard: profile.EnableDnsLeakGuard,
                            EnableEmergencyLockdown: false),
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Firewall DNS Leak Guard sync skipped softly during mode switch.");
                }
            }

            // Mirror changes immediately to Windows Service if connected
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                try
                {
                    _ = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration), cancellationToken).ConfigureAwait(false);
                    if (prevGamingEnabled != profile.EnableGamingEngine)
                    {
                        _ = await _serviceClient.SendAsync(
                            new IpcRequest(IpcRequestKind.SetGamingMode, BoolValue: profile.EnableGamingEngine),
                            cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "Service IPC sync after mode switch failed softly.");
                }
            }

            PublishState(new OperationModeState(
                selectedMode,
                effectiveMode,
                autoReason,
                autoDetail,
                profile.MinimizeVisualEffects,
                IsApplying: false));

            _logger.LogInformation(
                "Operation mode applied: selected={Selected}, effective={Effective}, reason={Reason}, resolver={Resolver}, minimizeFx={MinimizeFx}",
                selectedMode,
                effectiveMode,
                autoReason,
                validPrimary,
                profile.MinimizeVisualEffects);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "Failed to persist operation mode '{Mode}' due to storage access error.", selectedMode);
            PublishState(_state with { IsApplying = false });
        }
        finally
        {
            _applyGate.Release();
        }
    }

    private string ResolveValidResolverId(string candidateId, string fallbackId)
    {
        var all = _resolverLibrary.GetAll();
        if (all.Any(r => string.Equals(r.Id, candidateId, StringComparison.OrdinalIgnoreCase)))
        {
            return candidateId;
        }

        if (all.Any(r => string.Equals(r.Id, fallbackId, StringComparison.OrdinalIgnoreCase)))
        {
            return fallbackId;
        }

        return _resolverLibrary.GetPrimaryResolver().Id;
    }

    private void StartAutoMonitor()
    {
        if (_disposed)
        {
            return;
        }

        _autoTimer ??= new Timer(OnAutoMonitorTick, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        _autoTimer.Change(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    private void StopAutoMonitor()
    {
        _autoTimer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    private void OnAutoMonitorTick(object? state)
    {
        if (_disposed || _state.SelectedMode != AppOperationMode.Auto)
        {
            return;
        }

        if (Interlocked.Exchange(ref _autoTickInFlight, 1) != 0)
        {
            return;
        }

        _ = RunAutoEvaluationTickAsync();
    }

    private async Task RunAutoEvaluationTickAsync()
    {
        try
        {
            if (_disposed || _state.SelectedMode != AppOperationMode.Auto)
            {
                return;
            }

            var signals = await CollectAutoSignalsAsync(CancellationToken.None).ConfigureAwait(false);
            var decision = _evaluator.Evaluate(signals, _settings.Current.OperationMode.AutoRules, DateTimeOffset.UtcNow);
            if (decision.Changed && _state.SelectedMode == AppOperationMode.Auto)
            {
                await ApplyEffectiveModeAsync(
                    AppOperationMode.Auto,
                    decision.EffectiveMode,
                    decision.Reason,
                    decision.Detail,
                    CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Auto operation mode evaluation tick encountered an error.");
        }
        finally
        {
            Interlocked.Exchange(ref _autoTickInFlight, 0);
        }
    }

    private async Task<AutoModeSignals> CollectAutoSignalsAsync(CancellationToken cancellationToken)
    {
        var (isFullscreenD3D, fgProcess) = ProbeForegroundGameState();
        var rules = _settings?.Current.OperationMode.AutoRules;

        // Priority 1 (Gaming) short-circuit: avoid expensive threat/analytics probes when fullscreen D3D
        // or a user-configured custom game process is already active in the foreground.
        if (rules?.SwitchToGamingOnFullscreenGame == true && isFullscreenD3D)
        {
            return new AutoModeSignals(
                IsFullscreenD3DActive: true,
                ForegroundProcessName: fgProcess,
                HasActiveThreatAlert: false,
                BlockedQueriesPerMinute: 0,
                IsUntrustedNetwork: false);
        }

        if (!string.IsNullOrWhiteSpace(fgProcess)
            && rules?.CustomGameProcessNames is { Count: > 0 } customGames)
        {
            foreach (var g in customGames)
            {
                if (!string.IsNullOrWhiteSpace(g)
                    && fgProcess.Contains(g.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return new AutoModeSignals(
                        IsFullscreenD3DActive: isFullscreenD3D,
                        ForegroundProcessName: fgProcess,
                        HasActiveThreatAlert: false,
                        BlockedQueriesPerMinute: 0,
                        IsUntrustedNetwork: false);
                }
            }
        }

        var checkSecurity = rules?.SwitchToSecurityOnThreatOrSpike ?? true;
        double blockedPerMin = 0;
        var hasThreat = false;

        if (checkSecurity)
        {
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                try
                {
                    var snapshot = await _serviceClient.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
                    if (snapshot is not null)
                    {
                        blockedPerMin = snapshot.BlockedQueriesPerMinute;
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "Auto-mode status IPC probe skipped.");
                }
            }
            else if (_diagnostics is not null)
            {
                blockedPerMin = _diagnostics.GetBlockedQueriesPerMinute();
            }

            if (_threatIntel is not null
                && _connectionMonitor is not null
                && _threatIntel.GetStatus().IndicatorCount > 0)
            {
                try
                {
                    var conns = _connectionMonitor.CaptureSnapshot();
                    foreach (var c in conns)
                    {
                        if (!string.IsNullOrWhiteSpace(c.RemoteIp)
                            && _threatIntel.TryMatch(c.RemoteIp, protectedContext: null, out _))
                        {
                            hasThreat = true;
                            break;
                        }
                    }
                }
                catch
                {
                    hasThreat = false;
                }
            }
        }

        return new AutoModeSignals(
            IsFullscreenD3DActive: isFullscreenD3D,
            ForegroundProcessName: fgProcess,
            HasActiveThreatAlert: hasThreat,
            BlockedQueriesPerMinute: blockedPerMin,
            IsUntrustedNetwork: false);
    }

    private void PublishState(OperationModeState newState)
    {
        _state = newState;
        StateChanged?.Invoke(this, newState);
    }

    private (bool IsFullscreenD3D, string? ForegroundProcessName) ProbeForegroundGameState()
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, null);
        }

        var isD3DFullscreen = false;
        try
        {
            if (SHQueryUserNotificationState(out var qstate) == 0)
            {
                // 3 = QUNS_RUNNING_D3D_FULL_SCREEN, 1 = QUNS_NOT_PRESENT (screen locked / screensaver)
                if (qstate == 1)
                {
                    return (false, null);
                }

                isD3DFullscreen = qstate == 3;
            }
        }
        catch
        {
            isD3DFullscreen = false;
        }

        string? procName = null;
        try
        {
            var hwnd = GetForegroundWindow();
            if (hwnd != 0)
            {
                _ = GetWindowThreadProcessId(hwnd, out var pid);
                if (pid > 0)
                {
                    if (pid == _lastFgPid && !string.IsNullOrWhiteSpace(_lastFgProcessName))
                    {
                        return (isD3DFullscreen, _lastFgProcessName);
                    }

                    procName = QueryProcessNameByPid(pid);
                    _lastFgPid = pid;
                    _lastFgProcessName = procName;
                }
            }
        }
        catch
        {
            procName = null;
        }

        return (isD3DFullscreen, procName);
    }

    private static string? QueryProcessNameByPid(uint pid)
    {
        const uint ProcessQueryLimitedInformation = 0x1000;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle != nint.Zero)
        {
            try
            {
                Span<char> buffer = stackalloc char[512];
                var len = (uint)buffer.Length;
                if (QueryFullProcessImageNameW(handle, 0, ref buffer[0], ref len) && len > 0)
                {
                    var fullPath = buffer[..(int)len];
                    var lastSlash = fullPath.LastIndexOfAny('\\', '/');
                    var fileName = lastSlash >= 0 ? fullPath[(lastSlash + 1)..] : fullPath;
                    if (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        fileName = fileName[..^4];
                    }

                    return fileName.ToString();
                }
            }
            finally
            {
                _ = CloseHandle(handle);
            }
        }

        try
        {
            using var proc = Process.GetProcessById((int)pid);
            return proc.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _autoTimer?.Dispose();
        _autoTimer = null;
        _applyGate.Dispose();
    }

    [DllImport("shell32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int SHQueryUserNotificationState(out int pquns);

    [DllImport("user32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern nint GetForegroundWindow();

    [DllImport("user32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags, ref char lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);
}

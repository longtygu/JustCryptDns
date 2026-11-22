using JustCryptDns.Core.Configuration;

namespace JustCryptDns.Core.Services;

public enum AutoModeReason
{
    Normal,
    FullscreenGameDetected,
    KnownGameProcessDetected,
    ActiveThreatDetected,
    HighBlockedQuerySpike,
    UntrustedNetworkDetected,
}

public sealed record AutoModeSignals(
    bool IsFullscreenD3DActive,
    string? ForegroundProcessName,
    bool HasActiveThreatAlert,
    double BlockedQueriesPerMinute,
    bool IsUntrustedNetwork);

public sealed record AutoModeDecision(
    AppOperationMode EffectiveMode,
    AutoModeReason Reason,
    string? Detail,
    bool Changed);

/// <summary>
/// Pure, deterministic state machine for <see cref="AppOperationMode.Auto"/> with cooldown hysteresis
/// so brief Alt-Tabs or transient spikes do not flap between operating modes.
/// </summary>
public sealed class OperationModeEvaluator
{
    private AppOperationMode _currentEffectiveMode = AppOperationMode.Balanced;
    private AutoModeReason _currentReason = AutoModeReason.Normal;
    private string? _currentDetail;
    private DateTimeOffset _lastEscalationUtc = DateTimeOffset.MinValue;

    public AppOperationMode CurrentEffectiveMode => _currentEffectiveMode;

    public AutoModeReason CurrentReason => _currentReason;

    public string? CurrentDetail => _currentDetail;

    public void Reset(AppOperationMode initialMode = AppOperationMode.Balanced)
    {
        _currentEffectiveMode = initialMode == AppOperationMode.Auto ? AppOperationMode.Balanced : initialMode;
        _currentReason = AutoModeReason.Normal;
        _currentDetail = null;
        _lastEscalationUtc = DateTimeOffset.MinValue;
    }

    public AutoModeDecision Evaluate(AutoModeSignals signals, AutoModeRulesSettings rules, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(signals);
        ArgumentNullException.ThrowIfNull(rules);

        var (desiredMode, desiredReason, desiredDetail) = DetermineDesiredMode(signals, rules);

        // Escalations (Balanced -> Gaming/Security, or switching directly between Gaming <-> Security)
        // happen immediately and refresh the hold timer.
        if (desiredMode is AppOperationMode.Gaming or AppOperationMode.Security)
        {
            _lastEscalationUtc = nowUtc;
            var changed = desiredMode != _currentEffectiveMode
                || desiredReason != _currentReason
                || !string.Equals(desiredDetail, _currentDetail, StringComparison.Ordinal);
            _currentEffectiveMode = desiredMode;
            _currentReason = desiredReason;
            _currentDetail = desiredDetail;
            return new AutoModeDecision(_currentEffectiveMode, _currentReason, _currentDetail, changed);
        }

        // Downgrading back to Balanced requires CooldownSeconds of clear conditions.
        if (_currentEffectiveMode != AppOperationMode.Balanced)
        {
            var elapsed = nowUtc - _lastEscalationUtc;
            if (elapsed < TimeSpan.FromSeconds(rules.CooldownSeconds))
            {
                return new AutoModeDecision(_currentEffectiveMode, _currentReason, _currentDetail, Changed: false);
            }
        }

        var changedToBalanced = _currentEffectiveMode != AppOperationMode.Balanced || _currentReason != AutoModeReason.Normal;
        _currentEffectiveMode = AppOperationMode.Balanced;
        _currentReason = AutoModeReason.Normal;
        _currentDetail = null;
        return new AutoModeDecision(_currentEffectiveMode, _currentReason, _currentDetail, changedToBalanced);
    }

    private static (AppOperationMode Mode, AutoModeReason Reason, string? Detail) DetermineDesiredMode(
        AutoModeSignals signals,
        AutoModeRulesSettings rules)
    {
        // Priority 1: Gaming (fullscreen D3D or known/custom game process in foreground)
        if (rules.SwitchToGamingOnFullscreenGame)
        {
            if (rules.IsKnownGameProcess(signals.ForegroundProcessName))
            {
                return (AppOperationMode.Gaming, AutoModeReason.KnownGameProcessDetected, signals.ForegroundProcessName);
            }

            if (signals.IsFullscreenD3DActive)
            {
                return (AppOperationMode.Gaming, AutoModeReason.FullscreenGameDetected, signals.ForegroundProcessName);
            }
        }

        // Priority 2: Security (active threat alert, blocked query burst, or untrusted public network)
        if (rules.SwitchToSecurityOnThreatOrSpike)
        {
            if (signals.HasActiveThreatAlert)
            {
                return (AppOperationMode.Security, AutoModeReason.ActiveThreatDetected, null);
            }

            if (signals.BlockedQueriesPerMinute >= rules.HighBlockRateThresholdPerMinute)
            {
                return (AppOperationMode.Security, AutoModeReason.HighBlockedQuerySpike, $"{Math.Round(signals.BlockedQueriesPerMinute):0}/min");
            }

            if (signals.IsUntrustedNetwork)
            {
                return (AppOperationMode.Security, AutoModeReason.UntrustedNetworkDetected, null);
            }
        }

        return (AppOperationMode.Balanced, AutoModeReason.Normal, null);
    }
}

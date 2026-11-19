using System.Globalization;

namespace JustCryptDns.App.Controls;

public enum GaugeSeverity
{
    Neutral,
    Good,
    Warning,
    Danger,
}

/// <summary>
/// Pure math and auto-scaling helpers for dashboard speedometer gauges and live telemetry waveforms.
/// </summary>
public static class GaugeMath
{
    private static readonly double[] QueryCeilings =
    [
        50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000,
        25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 5_000_000,
    ];

    private static readonly double[] PingCeilings = [50, 100, 150, 200, 300, 500, 1000];
    private static readonly double[] SpeedCeilings = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000];

    public static double ComputeAutoScaleMax(double currentValue, double baseCeiling)
    {
        var floor = Math.Max(1.0, baseCeiling);
        var required = Math.Max(floor, Math.Max(0.0, currentValue) * 1.2);

        foreach (var candidate in QueryCeilings)
        {
            if (candidate >= required)
            {
                return candidate;
            }
        }

        var magnitude = Math.Pow(10.0, Math.Floor(Math.Log10(required)));
        return Math.Ceiling(required / magnitude) * magnitude;
    }

    public static string FormatCompactScaleLabel(double value)
    {
        if (value >= 1_000_000.0)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{value / 1_000_000.0:0.#}M");
        }

        if (value >= 1_000.0)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{value / 1_000.0:0.#}k");
        }

        return string.Create(CultureInfo.InvariantCulture, $"{value:0}");
    }

    public static double ComputeNormalized(double value, double min, double max)
    {
        if (max <= min || double.IsNaN(value) || double.IsInfinity(value))
        {
            return 0.0;
        }

        return Math.Clamp((value - min) / (max - min), 0.0, 1.0);
    }

    public static double StepNeedle(double current, double target, double dtSeconds, double responsiveness = 8.0)
    {
        var clampedDt = Math.Clamp(dtSeconds, 0.001, 0.25);
        var clampedTarget = Math.Clamp(target, 0.0, 1.0);
        var clampedCurrent = Math.Clamp(current, 0.0, 1.0);
        var alpha = 1.0 - Math.Exp(-Math.Max(0.5, responsiveness) * clampedDt);
        var next = clampedCurrent + ((clampedTarget - clampedCurrent) * alpha);
        return Math.Abs(clampedTarget - next) < 0.0002 ? clampedTarget : next;
    }

    public static double ComputeLiveIdleJitter(
        double timeSeconds,
        double normalizedValue,
        bool isActive,
        double phaseOffset,
        double pulseBoost)
    {
        if (!isActive)
        {
            return 0.0;
        }

        var wave = (Math.Sin((timeSeconds * 2.7) + phaseOffset) * 0.009)
            + (Math.Sin((timeSeconds * 6.3) + (phaseOffset * 1.7)) * 0.0045)
            + Math.Max(0.0, pulseBoost);

        var target = Math.Clamp(normalizedValue + wave, 0.015, 1.0);
        return target - normalizedValue;
    }

    public static double ComputePingWaveCeiling(IReadOnlyList<double> pingsMs)
    {
        ArgumentNullException.ThrowIfNull(pingsMs);
        double max = 0.0;
        for (var i = 0; i < pingsMs.Count; i++)
        {
            var val = pingsMs[i];
            if (!double.IsNaN(val) && !double.IsInfinity(val) && val > max)
            {
                max = val;
            }
        }

        var required = Math.Max(50.0, max * 1.2);
        foreach (var candidate in PingCeilings)
        {
            if (candidate >= required)
            {
                return candidate;
            }
        }

        return Math.Ceiling(required / 500.0) * 500.0;
    }

    public static double ComputeSpeedWaveCeiling(IReadOnlyList<double> speedsMbps)
    {
        ArgumentNullException.ThrowIfNull(speedsMbps);
        double max = 0.0;
        for (var i = 0; i < speedsMbps.Count; i++)
        {
            var val = speedsMbps[i];
            if (!double.IsNaN(val) && !double.IsInfinity(val) && val > max)
            {
                max = val;
            }
        }

        var required = Math.Max(1.0, max * 1.2);
        foreach (var candidate in SpeedCeilings)
        {
            if (candidate >= required)
            {
                return candidate;
            }
        }

        return Math.Ceiling(required / 500.0) * 500.0;
    }

    public static GaugeSeverity EvaluateLatencySeverity(double? latencyMs) => latencyMs switch
    {
        null => GaugeSeverity.Neutral,
        < 50.0 => GaugeSeverity.Good,
        <= 120.0 => GaugeSeverity.Warning,
        _ => GaugeSeverity.Danger,
    };

    public static GaugeSeverity EvaluateCacheHitSeverity(double cacheHitPercent, long totalQueries)
    {
        if (totalQueries <= 0)
        {
            return GaugeSeverity.Neutral;
        }

        return cacheHitPercent switch
        {
            >= 60.0 => GaugeSeverity.Good,
            >= 30.0 => GaugeSeverity.Neutral,
            _ => GaugeSeverity.Warning,
        };
    }
}

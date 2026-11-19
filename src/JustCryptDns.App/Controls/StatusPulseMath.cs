using JustCryptDns.Core.Configuration;

namespace JustCryptDns.App.Controls;

public readonly record struct StatusPulseFrame(double Intensity, double HaloOpacity, double HaloScale, double SurfaceOpacity);

/// <summary>
/// Pure math evaluating customizable visual pulse animations for the Dashboard protection shield and toggle button.
/// </summary>
public static class StatusPulseMath
{
    public static StatusPulseFrame Evaluate(StatusPulseStyle style, double timeSeconds)
    {
        var t = double.IsFinite(timeSeconds) && timeSeconds > 0.0 ? timeSeconds : 0.0;

        switch (style)
        {
            case StatusPulseStyle.Breathing:
            {
                var p = 0.5 - (0.5 * Math.Cos(2.0 * Math.PI * (t / 1.9)));
                return new StatusPulseFrame(p, 0.14 + (0.68 * p), 1.0 + (0.10 * p), 0.76 + (0.24 * p));
            }

            case StatusPulseStyle.GlowHalo:
            {
                var u = (t % 1.8) / 1.8;
                var p = Math.Sin(u * Math.PI);
                return new StatusPulseFrame(p, 0.88 * Math.Pow(1.0 - u, 1.35), 1.0 + (0.30 * u), 1.0);
            }

            case StatusPulseStyle.Heartbeat:
            {
                var u = (t % 2.0) / 2.0;
                var b1 = Math.Exp(-Math.Pow((u - 0.14) / 0.055, 2.0));
                var b2 = 0.72 * Math.Exp(-Math.Pow((u - 0.34) / 0.065, 2.0));
                var p = Math.Clamp(b1 + b2, 0.0, 1.0);
                return new StatusPulseFrame(p, 0.10 + (0.85 * p), 1.0 + (0.16 * p), 0.78 + (0.22 * p));
            }

            case StatusPulseStyle.Beacon:
            {
                var s = Math.Sin(2.0 * Math.PI * t);
                var p = Math.Clamp((s + 0.15) * 2.2, 0.0, 1.0);
                return new StatusPulseFrame(p, 0.08 + (0.88 * p), 1.0 + (0.12 * p), 0.65 + (0.35 * p));
            }

            case StatusPulseStyle.Off:
            default:
                return new StatusPulseFrame(0.0, 0.0, 1.0, 1.0);
        }
    }
}

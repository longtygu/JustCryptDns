using JustCryptDns.Core.Configuration;

namespace JustCryptDns.App.Services;

/// <summary>The material actually applied to the window.</summary>
public enum BackdropKind
{
    /// <summary>Opaque window, no composition effect (zero overhead).</summary>
    None,
    Mica,
    Acrylic,
    Blur,
}

/// <summary>Why the current backdrop state was chosen; drives the status text on the Appearance page.</summary>
public enum BackdropStatus
{
    Active,
    Disabled,
    ZeroTransparency,
    Unsupported,
    ApiFailed,
    WindowNotReady,
}

/// <summary>Materials this OS can provide.</summary>
public readonly record struct BackdropSupport(bool Mica, bool Acrylic, bool Blur)
{
    public bool Any => Mica || Acrylic || Blur;
}

public enum TransparencyLevel
{
    Opaque,
    Slight,
    Moderate,
    Strong,
    High,
}

/// <summary>
/// Pure appearance calculations (no WPF dependencies) so they can be unit tested.
/// </summary>
public static class AppearanceMath
{
    /// <summary>Requested transparency as a fraction 0–0.9, honoring the master switch.</summary>
    public static double RequestedFraction(AppearanceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return settings.TransparencyEnabled ? Math.Clamp(settings.Transparency, 0, AppearanceSettings.MaxTransparency) / 100.0 : 0;
    }

    // Readability: surfaces never go fully clear. At 90 % the window base keeps ~32 % opacity,
    // the sidebar ~41 % and content cards ~64 %, so text on cards keeps its contrast over any wallpaper.
    public static double WindowAlpha(double fraction) => 1 - (0.75 * Clamp(fraction));

    public static double SidebarAlpha(double fraction) => 1 - (0.65 * Clamp(fraction));

    public static double CardAlpha(double fraction) => 1 - (0.40 * Clamp(fraction));

    public static TransparencyLevel Level(int percent) => percent switch
    {
        <= 0 => TransparencyLevel.Opaque,
        <= 20 => TransparencyLevel.Slight,
        <= 40 => TransparencyLevel.Moderate,
        <= 60 => TransparencyLevel.Strong,
        _ => TransparencyLevel.High,
    };

    /// <summary>
    /// Chooses the backdrop to apply, falling back along Mica → Acrylic → Blur → None depending on OS support.
    /// </summary>
    public static (BackdropKind Kind, BackdropStatus Status) Resolve(AppearanceSettings settings, BackdropSupport support)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.TransparencyEnabled)
        {
            return (BackdropKind.None, BackdropStatus.Disabled);
        }

        if (settings.Transparency <= 0)
        {
            return (BackdropKind.None, BackdropStatus.ZeroTransparency);
        }

        BackdropKind[] chain = settings.Backdrop switch
        {
            BackdropPreference.Mica => [BackdropKind.Mica, BackdropKind.Acrylic, BackdropKind.Blur],
            BackdropPreference.Acrylic => [BackdropKind.Acrylic, BackdropKind.Blur],
            BackdropPreference.Blur => [BackdropKind.Blur],
            _ => [BackdropKind.Acrylic, BackdropKind.Blur],
        };

        foreach (var kind in chain)
        {
            var ok = kind switch
            {
                BackdropKind.Mica => support.Mica,
                BackdropKind.Acrylic => support.Acrylic,
                BackdropKind.Blur => support.Blur,
                _ => false,
            };
            if (ok)
            {
                return (kind, BackdropStatus.Active);
            }
        }

        return (BackdropKind.None, BackdropStatus.Unsupported);
    }

    public static double FontScale(TextSize size) => size switch
    {
        TextSize.Small => 0.92,
        TextSize.Large => 1.12,
        TextSize.ExtraLarge => 1.25,
        _ => 1.0,
    };

    public static double AnimationScale(AnimationLevel level) => level switch
    {
        AnimationLevel.Off => 0,
        AnimationLevel.Reduced => 0.5,
        _ => 1.0,
    };

    /// <summary>Card padding (uniform) and gap between cards, in DIPs.</summary>
    public static (double Padding, double Gap) Density(CardDensity density) => density switch
    {
        CardDensity.Compact => (14, 8),
        CardDensity.Spacious => (28, 16),
        _ => (20, 12),
    };

    private static double Clamp(double fraction) => Math.Clamp(fraction, 0, 0.9);
}

using System.Windows;
using System.Windows.Media;
using JustCryptDns.App.Controls;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

public sealed record AppearanceState(BackdropKind Backdrop, BackdropStatus Status, double EffectiveTransparency, string EffectiveAccent);

public interface IAppearanceService
{
    BackdropSupport Support { get; }

    bool SupportsCornerStyle { get; }

    AppearanceState State { get; }

    /// <summary>Raised on the UI thread after appearance was (re)applied.</summary>
    event EventHandler<AppearanceState>? Applied;

    /// <summary>Registers the main window for backdrop/corner handling. Call after its handle exists.</summary>
    void AttachWindow(Window window);

    /// <summary>Applies all appearance settings. Idempotent and cheap when nothing changed.</summary>
    void Apply(AppearanceSettings settings);
}

/// <summary>
/// Orchestrates theme palette, accent, surface opacity, custom tint, typography scale, density, motion,
/// background decoration, UI scale and the window backdrop.
/// Surface brushes are long-lived mutable instances registered once in application resources;
/// updates only change their Color, so slider drags do not trigger resource-tree invalidation.
/// </summary>
public sealed class AppearanceService : IAppearanceService
{
    // Must match the defaults declared in Styles/Controls.xaml.
    internal static readonly (string Key, double Size)[] FontSizes =
    [
        ("Font.Size.Small", 11),
        ("Font.Size.Label", 11.5),
        ("Font.Size.Caption", 12),
        ("Font.Size.Mono", 12.5),
        ("Font.Size.Body", 13),
        ("Font.Size.BodyLarge", 13.5),
        ("Font.Size.AppName", 14),
        ("Font.Size.Section", 15),
        ("Font.Size.Heading", 17),
        ("Font.Size.Hero", 22),
        ("Font.Size.Metric", 24),
        ("Font.Size.Title", 26),
    ];

    private readonly IThemeService _theme;
    private readonly ILogger<AppearanceService> _logger;
    private readonly Dictionary<string, Color> _surfaceColors = [];
    private AppearanceSettings _settings = new();
    private WindowBackdropController? _backdrop;

    public AppearanceService(IThemeService theme, ILogger<AppearanceService> logger)
    {
        _theme = theme;
        _logger = logger;
        Support = WindowBackdropController.DetectSupport();
        _theme.ThemeChanged += (_, _) => ApplyVisuals();
        State = new AppearanceState(BackdropKind.None, BackdropStatus.WindowNotReady, 0, AppearanceSettings.DefaultAccentColor);
        _logger.LogInformation("Backdrop support on {Os}: {Support}", WindowsVersion.DisplayName, Support);
    }

    public BackdropSupport Support { get; }

    public bool SupportsCornerStyle => DwmInterop.SupportsCornerPreference;

    public AppearanceState State { get; private set; }

    public event EventHandler<AppearanceState>? Applied;

    public void AttachWindow(Window window)
    {
        _backdrop = new WindowBackdropController(window, _logger);
        ApplyVisuals();
    }

    public void Apply(AppearanceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;
        var accent = EffectiveAccent(settings);
        _theme.Apply(settings.Theme, settings.CustomBaseTheme, accent); // raises ThemeChanged only when something changed
        ApplyVisuals();
    }

    private static string EffectiveAccent(AppearanceSettings settings) =>
        settings.UseSystemAccent && SystemAccent.TryRead() is { } system ? system : settings.AccentColor;

    private void ApplyVisuals()
    {
        var app = Application.Current;
        if (app is null || _theme.Palette is null)
        {
            return;
        }

        var resources = app.Resources;
        var settings = _settings;

        // 1. Backdrop
        var (kind, status) = AppearanceMath.Resolve(settings, Support);
        if (_backdrop is null || !_backdrop.IsReady)
        {
            status = kind == BackdropKind.None ? status : BackdropStatus.WindowNotReady;
            kind = BackdropKind.None;
        }
        else if (!_backdrop.Apply(kind, _theme.EffectiveTheme == AppTheme.Dark, settings.CornerStyle))
        {
            kind = BackdropKind.None;
            status = BackdropStatus.ApiFailed;
        }

        // Without an active backdrop the window stays fully opaque (transparency would only show black).
        var fraction = kind == BackdropKind.None ? 0 : AppearanceMath.RequestedFraction(settings);

        // 2. Surfaces (theme palette, optional custom tint, opacity)
        var tint = settings.Theme == AppTheme.Custom ? (Color?)ParseColor(settings.CustomTintColor) : null;
        SetSurface(resources, "Brush.WindowBackground", "Color.WindowBackground", tint, 0.10, AppearanceMath.WindowAlpha(fraction));
        SetSurface(resources, "Brush.Sidebar", "Color.Sidebar", tint, 0.10, AppearanceMath.SidebarAlpha(fraction));
        SetSurface(resources, "Brush.Card", "Color.Card", tint, 0.06, AppearanceMath.CardAlpha(fraction));
        SetSurface(resources, "Brush.CardHover", "Color.CardHover", tint, 0.08, AppearanceMath.CardAlpha(fraction));
        SetSurface(resources, "Brush.CardBorder", "Color.CardBorder", tint, 0.12, 1.0);

        // 3. Background decoration
        SetDecoration(resources, settings.Background, _theme.EffectiveTheme);

        // 4. Typography
        var fontScale = AppearanceMath.FontScale(settings.TextSize);
        foreach (var (key, size) in FontSizes)
        {
            SetIfChanged(resources, key, Math.Round(size * fontScale, 1));
        }

        // 5. Density
        var (padding, gap) = AppearanceMath.Density(settings.Density);
        SetIfChanged(resources, "Card.Padding", new Thickness(padding + 4, padding, padding + 4, padding));
        SetIfChanged(resources, "Card.PaddingSmall", new Thickness(padding - 2, padding - 4, padding - 2, padding - 4));
        SetIfChanged(resources, "Card.Gap", new Thickness(0, 0, 0, gap));
        SetIfChanged(resources, "Card.GapGrid", new Thickness(0, 0, gap, gap));
        SetIfChanged(resources, "Card.GridCompensation", new Thickness(0, 0, -gap, 0));

        // 6. UI scale and motion
        SetIfChanged(resources, "Ui.Scale", settings.UiScalePercent / 100.0);
        AnimatedContentControl.AnimationScale = AppearanceMath.AnimationScale(settings.Animations);

        State = new AppearanceState(kind, status, fraction, EffectiveAccent(settings));
        Applied?.Invoke(this, State);
    }

    private void SetSurface(ResourceDictionary resources, string brushKey, string colorKey, Color? tint, double tintAmount, double alpha)
    {
        var baseColor = _theme.Palette![colorKey] is Color c ? c : Colors.Black;
        if (tint is { } t)
        {
            baseColor = ColorMath.Mix(baseColor, t, tintAmount);
        }

        var color = ColorMath.WithAlpha(baseColor, alpha);
        if (_surfaceColors.TryGetValue(brushKey, out var existing) && existing == color && resources.Contains(brushKey))
        {
            return;
        }

        var brush = new SolidColorBrush(color);
        brush.Freeze();
        _surfaceColors[brushKey] = color;
        resources[brushKey] = brush;
    }

    private void SetDecoration(ResourceDictionary resources, BackgroundStyle style, AppTheme effective)
    {
        Brush brush;
        if (style == BackgroundStyle.AccentTint && resources["Color.Accent"] is Color accent)
        {
            var strength = effective == AppTheme.Dark ? 0.16 : 0.10;
            var radial = new RadialGradientBrush
            {
                Center = new Point(0.15, 0),
                GradientOrigin = new Point(0.15, 0),
                RadiusX = 0.9,
                RadiusY = 0.9,
            };
            radial.GradientStops.Add(new GradientStop(ColorMath.WithAlpha(accent, strength), 0));
            radial.GradientStops.Add(new GradientStop(ColorMath.WithAlpha(accent, 0), 1));
            radial.Freeze();
            brush = radial;
        }
        else
        {
            brush = Brushes.Transparent;
        }

        resources["Brush.BackgroundDecoration"] = brush;
    }

    private static void SetIfChanged(ResourceDictionary resources, string key, object value)
    {
        if (!resources.Contains(key) || !Equals(resources[key], value))
        {
            resources[key] = value;
        }
    }

    private static Color ParseColor(string hex) => (Color)ColorConverter.ConvertFromString(hex);
}

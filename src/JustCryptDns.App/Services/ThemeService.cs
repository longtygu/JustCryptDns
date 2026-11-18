using System.Windows;
using System.Windows.Media;
using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.App.Services;

public interface IThemeService
{
    /// <summary>The effective palette: always <see cref="AppTheme.Dark"/> or <see cref="AppTheme.Light"/>.</summary>
    AppTheme EffectiveTheme { get; }

    /// <summary>The active palette dictionary (Dark.xaml or Light.xaml).</summary>
    ResourceDictionary? Palette { get; }

    /// <summary>Raised after the palette or accent changed (including Windows app-mode changes in System mode).</summary>
    event EventHandler? ThemeChanged;

    /// <param name="theme">Requested theme.</param>
    /// <param name="customBase">Base palette when <paramref name="theme"/> is <see cref="AppTheme.Custom"/>.</param>
    /// <param name="accentHex">Accent as <c>#RRGGBB</c>.</param>
    void Apply(AppTheme theme, AppTheme customBase, string accentHex);
}

/// <summary>
/// Swaps the Dark/Light palette dictionary at runtime and maintains accent brushes.
/// Accent brushes are long-lived mutable instances: changing the accent only updates their Color,
/// which avoids resource-tree invalidation and keeps live previews cheap.
/// </summary>
public sealed class ThemeService : IThemeService, IDisposable
{
    private static readonly Uri DarkUri = new("pack://application:,,,/JustCryptDns;component/Themes/Dark.xaml");
    private static readonly Uri LightUri = new("pack://application:,,,/JustCryptDns;component/Themes/Light.xaml");

    private static readonly string[] AccentKeys =
        ["Brush.Accent", "Brush.AccentHover", "Brush.AccentPressed", "Brush.AccentSubtle", "Brush.AccentText", "Brush.OnAccent"];

    private readonly ILogger<ThemeService> _logger;
    private readonly Dictionary<string, Color> _accentColors = [];
    private AppTheme _requested = AppTheme.Dark;
    private AppTheme _customBase = AppTheme.Dark;
    private string _accent = AppearanceSettings.DefaultAccentColor;
    private string? _appliedAccent;
    private bool _systemHooked;

    public ThemeService(ILogger<ThemeService> logger) => _logger = logger;

    public AppTheme EffectiveTheme { get; private set; } = AppTheme.Dark;

    public ResourceDictionary? Palette { get; private set; }

    public event EventHandler? ThemeChanged;

    public void Apply(AppTheme theme, AppTheme customBase, string accentHex)
    {
        _requested = theme;
        _customBase = customBase is AppTheme.Light ? AppTheme.Light : AppTheme.Dark;
        _accent = ColorText.IsValidRgb(accentHex) ? accentHex : AppearanceSettings.DefaultAccentColor;
        UpdateSystemHook();
        ApplyCore(force: false);
    }

    /// <summary>Reads <c>AppsUseLightTheme</c>; defaults to dark if unavailable.</summary>
    public static AppTheme ReadWindowsAppTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int value && value == 1 ? AppTheme.Light : AppTheme.Dark;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            return AppTheme.Dark;
        }
    }

    public static AppTheme ResolveEffective(AppTheme requested, AppTheme customBase, Func<AppTheme> windowsTheme) => requested switch
    {
        AppTheme.System => windowsTheme(),
        AppTheme.Custom => customBase is AppTheme.Light ? AppTheme.Light : AppTheme.Dark,
        AppTheme.Light => AppTheme.Light,
        _ => AppTheme.Dark,
    };

    private void ApplyCore(bool force)
    {
        var app = Application.Current;
        if (app is null)
        {
            return;
        }

        var effective = ResolveEffective(_requested, _customBase, ReadWindowsAppTheme);
        var paletteChanged = Palette is null || effective != EffectiveTheme;
        if (paletteChanged)
        {
            var palette = new ResourceDictionary { Source = effective == AppTheme.Light ? LightUri : DarkUri };
            var merged = app.Resources.MergedDictionaries;
            if (Palette is not null && merged.IndexOf(Palette) is var index and >= 0)
            {
                merged[index] = palette;
            }
            else
            {
                merged.Insert(0, palette);
            }

            Palette = palette;
            EffectiveTheme = effective;
        }

        var accentKey = _accent + "|" + effective;
        if (!paletteChanged && !force && accentKey == _appliedAccent)
        {
            return;
        }

        ApplyAccent(app.Resources, _accent, effective);
        _appliedAccent = accentKey;
        _logger.LogInformation("Theme applied: requested={Requested} effective={Effective} accent={Accent}", _requested, effective, _accent);
        ThemeChanged?.Invoke(this, EventArgs.Empty);
    }

    private void ApplyAccent(ResourceDictionary target, string hex, AppTheme effective)
    {
        var colors = ComputeAccent((Color)ColorConverter.ConvertFromString(hex), effective);
        for (var i = 0; i < AccentKeys.Length; i++)
        {
            var key = AccentKeys[i];
            if (_accentColors.TryGetValue(key, out var existing) && existing == colors[i] && target.Contains(key))
            {
                continue;
            }

            var brush = new SolidColorBrush(colors[i]);
            brush.Freeze();
            _accentColors[key] = colors[i];
            target[key] = brush;
        }

        if (!target.Contains("Color.Accent") || (Color)target["Color.Accent"] != colors[0])
        {
            target["Color.Accent"] = colors[0];
        }
    }

    /// <summary>Accent, hover, pressed, subtle, text and on-accent colors for the given base palette.</summary>
    internal static Color[] ComputeAccent(Color accent, AppTheme effective)
    {
        var dark = effective == AppTheme.Dark;
        var hover = dark ? ColorMath.Mix(accent, Colors.White, 0.15) : ColorMath.Mix(accent, Colors.Black, 0.10);
        var pressed = dark ? ColorMath.Mix(accent, Colors.Black, 0.15) : ColorMath.Mix(accent, Colors.Black, 0.20);
        var text = dark ? ColorMath.Mix(accent, Colors.White, 0.35) : ColorMath.Mix(accent, Colors.Black, 0.20);
        var subtle = Color.FromArgb(dark ? (byte)0x30 : (byte)0x1F, accent.R, accent.G, accent.B);
        var darkInk = Color.FromRgb(0x10, 0x12, 0x16);
        var onAccent = ColorMath.ContrastRatio(accent, darkInk) >= ColorMath.ContrastRatio(accent, Colors.White)
            ? darkInk
            : Colors.White;
        return [accent, hover, pressed, subtle, text, onAccent];
    }

    private void UpdateSystemHook()
    {
        var want = _requested == AppTheme.System;
        if (want && !_systemHooked)
        {
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            _systemHooked = true;
        }
        else if (!want && _systemHooked)
        {
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            _systemHooked = false;
        }
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category != UserPreferenceCategory.General)
        {
            return;
        }

        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            if (_requested == AppTheme.System && ReadWindowsAppTheme() != EffectiveTheme)
            {
                ApplyCore(force: true);
            }
        });
    }

    public void Dispose()
    {
        if (_systemHooked)
        {
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            _systemHooked = false;
        }
    }
}

public static class ColorMath
{
    public static Color Mix(Color a, Color b, double amount) => Color.FromArgb(
        a.A,
        (byte)Math.Round(a.R + ((b.R - a.R) * amount)),
        (byte)Math.Round(a.G + ((b.G - a.G) * amount)),
        (byte)Math.Round(a.B + ((b.B - a.B) * amount)));

    public static Color WithAlpha(Color c, double alpha) =>
        Color.FromArgb((byte)Math.Round(Math.Clamp(alpha, 0, 1) * 255), c.R, c.G, c.B);

    public static double RelativeLuminance(Color c)
    {
        static double Channel(byte v)
        {
            var s = v / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        return (0.2126 * Channel(c.R)) + (0.7152 * Channel(c.G)) + (0.0722 * Channel(c.B));
    }

    /// <summary>WCAG contrast ratio between two opaque colors (1–21).</summary>
    public static double ContrastRatio(Color a, Color b)
    {
        var la = RelativeLuminance(a);
        var lb = RelativeLuminance(b);
        return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
    }
}

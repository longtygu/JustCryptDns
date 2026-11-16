using System.Windows;
using System.Windows.Media;
using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.App.Services;

public interface IThemeService
{
    /// <summary>The effective (resolved) theme: never <see cref="AppTheme.System"/>.</summary>
    AppTheme EffectiveTheme { get; }

    event EventHandler? ThemeChanged;

    void Apply(AppTheme theme, string accentHex);
}

/// <summary>
/// Swaps the Dark/Light palette dictionary at runtime and generates accent brushes from the user's color.
/// Tracks the Windows app-mode setting when <see cref="AppTheme.System"/> is selected.
/// </summary>
public sealed class ThemeService : IThemeService, IDisposable
{
    private static readonly Uri DarkUri = new("pack://application:,,,/JustCryptDns;component/Themes/Dark.xaml");
    private static readonly Uri LightUri = new("pack://application:,,,/JustCryptDns;component/Themes/Light.xaml");

    private readonly ILogger<ThemeService> _logger;
    private AppTheme _requested = AppTheme.Dark;
    private string _accent = AppearanceSettings.DefaultAccentColor;
    private ResourceDictionary? _palette;
    private bool _systemHooked;

    public ThemeService(ILogger<ThemeService> logger) => _logger = logger;

    public AppTheme EffectiveTheme { get; private set; } = AppTheme.Dark;

    public event EventHandler? ThemeChanged;

    public void Apply(AppTheme theme, string accentHex)
    {
        _requested = theme;
        _accent = ColorText.IsValidRgb(accentHex) ? accentHex : AppearanceSettings.DefaultAccentColor;
        UpdateSystemHook();
        ApplyCore();
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

    private void ApplyCore()
    {
        var effective = _requested == AppTheme.System ? ReadWindowsAppTheme() : _requested;
        var app = Application.Current;
        if (app is null)
        {
            return;
        }

        if (_palette is null || effective != EffectiveTheme)
        {
            var palette = new ResourceDictionary { Source = effective == AppTheme.Light ? LightUri : DarkUri };
            var merged = app.Resources.MergedDictionaries;
            if (_palette is not null)
            {
                var index = merged.IndexOf(_palette);
                merged[index] = palette;
            }
            else
            {
                merged.Insert(0, palette);
            }

            _palette = palette;
        }

        EffectiveTheme = effective;
        ApplyAccent(app.Resources, _accent, effective);
        _logger.LogInformation("Theme applied: requested={Requested} effective={Effective} accent={Accent}", _requested, effective, _accent);
        ThemeChanged?.Invoke(this, EventArgs.Empty);
    }

    internal static void ApplyAccent(ResourceDictionary target, string hex, AppTheme effective)
    {
        var accent = (Color)ColorConverter.ConvertFromString(hex);
        var hover = effective == AppTheme.Dark ? Mix(accent, Colors.White, 0.15) : Mix(accent, Colors.Black, 0.10);
        var pressed = effective == AppTheme.Dark ? Mix(accent, Colors.Black, 0.15) : Mix(accent, Colors.Black, 0.20);
        var text = effective == AppTheme.Dark ? Mix(accent, Colors.White, 0.35) : Mix(accent, Colors.Black, 0.20);
        var subtle = Color.FromArgb(effective == AppTheme.Dark ? (byte)0x30 : (byte)0x1F, accent.R, accent.G, accent.B);
        var onAccent = RelativeLuminance(accent) > 0.45 ? Color.FromRgb(0x10, 0x12, 0x16) : Colors.White;

        Set(target, "Brush.Accent", accent);
        Set(target, "Brush.AccentHover", hover);
        Set(target, "Brush.AccentPressed", pressed);
        Set(target, "Brush.AccentSubtle", subtle);
        Set(target, "Brush.AccentText", text);
        Set(target, "Brush.OnAccent", onAccent);
        target["Color.Accent"] = accent;
    }

    internal static double RelativeLuminance(Color c)
    {
        static double Channel(byte v)
        {
            var s = v / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        return (0.2126 * Channel(c.R)) + (0.7152 * Channel(c.G)) + (0.0722 * Channel(c.B));
    }

    private static Color Mix(Color a, Color b, double amount) => Color.FromRgb(
        (byte)Math.Round(a.R + ((b.R - a.R) * amount)),
        (byte)Math.Round(a.G + ((b.G - a.G) * amount)),
        (byte)Math.Round(a.B + ((b.B - a.B) * amount)));

    private static void Set(ResourceDictionary target, string key, Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        target[key] = brush;
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
                ApplyCore();
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

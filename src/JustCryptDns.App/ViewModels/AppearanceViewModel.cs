using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;

namespace JustCryptDns.App.ViewModels;

/// <summary>A selectable color chip.</summary>
public sealed partial class ColorSwatch : ObservableObject
{
    public ColorSwatch(string hex)
    {
        Hex = hex;
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        Brush = brush;
    }

    public string Hex { get; }

    public Brush Brush { get; }

    [ObservableProperty]
    private bool _isSelected;
}

/// <summary>
/// Appearance settings page. Every change is applied immediately (via <see cref="ISettingsService.UpdateDeferred"/>,
/// which raises Changed synchronously) and persisted once the user pauses.
/// </summary>
public sealed partial class AppearanceViewModel : PageViewModel
{
    public static readonly IReadOnlyList<string> AccentPresets =
    [
        "#4F8CFF", "#2563EB", "#7B5CFF", "#A855F7", "#EC4899", "#EF4444",
        "#F97316", "#EAB308", "#22C55E", "#10B981", "#14B8A6", "#06B6D4",
    ];

    public static readonly IReadOnlyList<string> TintPresets =
    [
        "#7B5CFF", "#4F8CFF", "#14B8A6", "#22C55E", "#F97316", "#EC4899", "#64748B", "#A16207",
    ];

    private readonly ISettingsService _settings;
    private readonly IAppearanceService _appearance;
    private readonly INavigationService _navigation;
    private bool _loading;

    [ObservableProperty] private AppTheme _theme;
    [ObservableProperty] private AppTheme _customBaseTheme;
    [ObservableProperty] private string _customTintColor = string.Empty;
    [ObservableProperty] private string _accentColor = string.Empty;
    [ObservableProperty] private bool _useSystemAccent;
    [ObservableProperty] private bool _transparencyEnabled;
    [ObservableProperty] private int _transparency;
    [ObservableProperty] private BackdropPreference _backdrop;
    [ObservableProperty] private BackgroundStyle _background;
    [ObservableProperty] private bool _sidebarCollapsed;
    [ObservableProperty] private CardDensity _density;
    [ObservableProperty] private WindowCornerStyle _cornerStyle;
    [ObservableProperty] private int _uiScalePercent;
    [ObservableProperty] private TextSize _textSize;
    [ObservableProperty] private AnimationLevel _animations;

    [ObservableProperty] private string _accentInput = string.Empty;
    [ObservableProperty] private bool _isAccentInputInvalid;
    [ObservableProperty] private BackdropKind _activeBackdrop;
    [ObservableProperty] private BackdropStatus _backdropStatus;
    [ObservableProperty] private string _effectiveAccent = string.Empty;

    public AppearanceViewModel(ISettingsService settings, IAppearanceService appearance, INavigationService navigation)
        : base("Appearance_Title", "Page_Appearance_Subtitle")
    {
        _settings = settings;
        _appearance = appearance;
        _navigation = navigation;

        AccentSwatches = new ObservableCollection<ColorSwatch>(AccentPresets.Select(h => new ColorSwatch(h)));
        TintSwatches = new ObservableCollection<ColorSwatch>(TintPresets.Select(h => new ColorSwatch(h)));

        LoadFrom(settings.Current.Appearance);
        UpdateState(appearance.State);
    }

    public ObservableCollection<ColorSwatch> AccentSwatches { get; }

    public ObservableCollection<ColorSwatch> TintSwatches { get; }

    public bool IsTransparencySupported => _appearance.Support.Any;

    public bool IsMicaSupported => _appearance.Support.Mica;

    public bool IsAcrylicSupported => _appearance.Support.Acrylic;

    public bool IsBlurSupported => _appearance.Support.Blur;

    public bool IsCornerStyleSupported => _appearance.SupportsCornerStyle;

    public bool IsCustomTheme => Theme == AppTheme.Custom;

    public TransparencyLevel TransparencyLevel => AppearanceMath.Level(Transparency);

    public override void OnNavigatedTo()
    {
        _settings.Changed += OnSettingsChanged;
        _appearance.Applied += OnAppearanceApplied;
    }

    public override void OnNavigatedFrom() => Unsubscribe();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Unsubscribe();
        }

        base.Dispose(disposing);
    }

    [RelayCommand]
    private void SelectAccent(string? hex)
    {
        if (ColorText.NormalizeRgb(hex) is { } value)
        {
            UseSystemAccent = false;
            AccentColor = value;
        }
    }

    [RelayCommand]
    private void ApplyAccentInput()
    {
        var value = ColorText.NormalizeRgb(AccentInput);
        IsAccentInputInvalid = value is null;
        if (value is not null)
        {
            SelectAccent(value);
        }
    }

    [RelayCommand]
    private void SelectTint(string? hex)
    {
        if (ColorText.NormalizeRgb(hex) is { } value)
        {
            CustomTintColor = value;
        }
    }

    [RelayCommand]
    private void Reset()
    {
        _settings.UpdateDeferred(s => s.Appearance = new AppearanceSettings());
        LoadFrom(_settings.Current.Appearance);
    }

    [RelayCommand]
    private void Back() => _navigation.Navigate(PageKeys.Settings);

    partial void OnThemeChanged(AppTheme value)
    {
        OnPropertyChanged(nameof(IsCustomTheme));
        Save(s => s.Theme = value);
    }

    partial void OnCustomBaseThemeChanged(AppTheme value) => Save(s => s.CustomBaseTheme = value);

    partial void OnCustomTintColorChanged(string value)
    {
        Mark(TintSwatches, value);
        Save(s => s.CustomTintColor = value);
    }

    partial void OnAccentColorChanged(string value)
    {
        Mark(AccentSwatches, UseSystemAccent ? null : value);
        if (!_loading)
        {
            AccentInput = value;
            IsAccentInputInvalid = false;
        }

        Save(s => s.AccentColor = value);
    }

    partial void OnUseSystemAccentChanged(bool value)
    {
        Mark(AccentSwatches, value ? null : AccentColor);
        Save(s => s.UseSystemAccent = value);
    }

    partial void OnTransparencyEnabledChanged(bool value) => Save(s => s.TransparencyEnabled = value);

    partial void OnTransparencyChanged(int value)
    {
        OnPropertyChanged(nameof(TransparencyLevel));
        Save(s => s.Transparency = value);
    }

    partial void OnBackdropChanged(BackdropPreference value) => Save(s => s.Backdrop = value);

    partial void OnBackgroundChanged(BackgroundStyle value) => Save(s => s.Background = value);

    partial void OnSidebarCollapsedChanged(bool value) => Save(s => s.SidebarCollapsed = value);

    partial void OnDensityChanged(CardDensity value) => Save(s => s.Density = value);

    partial void OnCornerStyleChanged(WindowCornerStyle value) => Save(s => s.CornerStyle = value);

    partial void OnUiScalePercentChanged(int value) => Save(s => s.UiScalePercent = value);

    partial void OnTextSizeChanged(TextSize value) => Save(s => s.TextSize = value);

    partial void OnAnimationsChanged(AnimationLevel value) => Save(s => s.Animations = value);

    private void Save(Action<AppearanceSettings> mutate)
    {
        if (_loading)
        {
            return;
        }

        _settings.UpdateDeferred(s => mutate(s.Appearance));
    }

    private void LoadFrom(AppearanceSettings a)
    {
        _loading = true;
        try
        {
            Theme = a.Theme;
            CustomBaseTheme = a.CustomBaseTheme;
            CustomTintColor = a.CustomTintColor;
            UseSystemAccent = a.UseSystemAccent;
            AccentColor = a.AccentColor;
            TransparencyEnabled = a.TransparencyEnabled;
            Transparency = a.Transparency;
            Backdrop = a.Backdrop;
            Background = a.Background;
            SidebarCollapsed = a.SidebarCollapsed;
            Density = a.Density;
            CornerStyle = a.CornerStyle;
            UiScalePercent = a.UiScalePercent;
            TextSize = a.TextSize;
            Animations = a.Animations;
            AccentInput = a.AccentColor;
            IsAccentInputInvalid = false;
            Mark(AccentSwatches, a.UseSystemAccent ? null : a.AccentColor);
            Mark(TintSwatches, a.CustomTintColor);
        }
        finally
        {
            _loading = false;
        }
    }

    private static void Mark(IEnumerable<ColorSwatch> swatches, string? selected)
    {
        foreach (var swatch in swatches)
        {
            swatch.IsSelected = string.Equals(swatch.Hex, selected, StringComparison.OrdinalIgnoreCase);
        }
    }

    private void UpdateState(AppearanceState state)
    {
        ActiveBackdrop = state.Backdrop;
        BackdropStatus = state.Status;
        EffectiveAccent = state.EffectiveAccent;
    }

    private void OnAppearanceApplied(object? sender, AppearanceState state) => UpdateState(state);

    private void OnSettingsChanged(object? sender, AppSettings settings)
    {
        // External changes (e.g. sidebar toggle in the shell) are reflected here; own changes are no-ops.
        if (settings.Appearance.SidebarCollapsed != SidebarCollapsed)
        {
            _loading = true;
            SidebarCollapsed = settings.Appearance.SidebarCollapsed;
            _loading = false;
        }
    }

    private void Unsubscribe()
    {
        _settings.Changed -= OnSettingsChanged;
        _appearance.Applied -= OnAppearanceApplied;
    }
}

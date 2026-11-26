using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using JustCryptDns.Core.Configuration;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Seamless 5-switch segmented bar for switching between HighSpeed, Gaming, Balanced, Auto, and Security modes
/// with smooth sliding indicator animation and luminous pulsing feedback on the active switch.
/// </summary>
public partial class OperationModeSwitcherControl : UserControl
{
    private static readonly Color ColorHighSpeed = Color.FromRgb(0xFF, 0x9F, 0x1C);
    private static readonly Color ColorGaming = Color.FromRgb(0x00, 0xD4, 0xFF);
    private static readonly Color ColorBalanced = Color.FromRgb(0x4F, 0x8C, 0xFF);
    private static readonly Color ColorAuto = Color.FromRgb(0x2D, 0xD4, 0xBF);
    private static readonly Color ColorSecurity = Color.FromRgb(0x3D, 0xD6, 0x8C);

    public static readonly DependencyProperty SelectedModeProperty = DependencyProperty.Register(
        nameof(SelectedMode),
        typeof(AppOperationMode),
        typeof(OperationModeSwitcherControl),
        new PropertyMetadata(AppOperationMode.Balanced, OnModeChanged));

    public static readonly DependencyProperty EffectiveModeProperty = DependencyProperty.Register(
        nameof(EffectiveMode),
        typeof(AppOperationMode),
        typeof(OperationModeSwitcherControl),
        new PropertyMetadata(AppOperationMode.Balanced, OnVisualPropertyChanged));

    public static readonly DependencyProperty MinimizeVisualEffectsProperty = DependencyProperty.Register(
        nameof(MinimizeVisualEffects),
        typeof(bool),
        typeof(OperationModeSwitcherControl),
        new PropertyMetadata(false, OnVisualPropertyChanged));

    public static readonly DependencyProperty ModeSelectedCommandProperty = DependencyProperty.Register(
        nameof(ModeSelectedCommand),
        typeof(ICommand),
        typeof(OperationModeSwitcherControl),
        new PropertyMetadata(null));

    private DropShadowEffect? _thumbGlow;
    private double _lastPulsePhase;

    public OperationModeSwitcherControl()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            UpdateThumbPosition(animate: false);
            UpdateVisuals();
            StepPulse(_lastPulsePhase);
        };
    }

    public AppOperationMode SelectedMode
    {
        get => (AppOperationMode)GetValue(SelectedModeProperty);
        set => SetValue(SelectedModeProperty, value);
    }

    public AppOperationMode EffectiveMode
    {
        get => (AppOperationMode)GetValue(EffectiveModeProperty);
        set => SetValue(EffectiveModeProperty, value);
    }

    public bool MinimizeVisualEffects
    {
        get => (bool)GetValue(MinimizeVisualEffectsProperty);
        set => SetValue(MinimizeVisualEffectsProperty, value);
    }

    public ICommand? ModeSelectedCommand
    {
        get => (ICommand?)GetValue(ModeSelectedCommandProperty);
        set => SetValue(ModeSelectedCommandProperty, value);
    }

    private static void OnModeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is OperationModeSwitcherControl ctrl)
        {
            ctrl.UpdateVisuals();
            ctrl.UpdateThumbPosition(animate: ctrl.IsLoaded && !ctrl.MinimizeVisualEffects);
            ctrl.StepPulse(ctrl._lastPulsePhase);
        }
    }

    private static void OnVisualPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is OperationModeSwitcherControl ctrl)
        {
            ctrl.UpdateVisuals();
            ctrl.StepPulse(ctrl._lastPulsePhase);
        }
    }

    private void OnTrackSizeChanged(object sender, SizeChangedEventArgs e)
    {
        UpdateThumbPosition(animate: false);
    }

    private void OnHighSpeedClick(object sender, RoutedEventArgs e) => SelectMode(AppOperationMode.HighSpeed);
    private void OnGamingClick(object sender, RoutedEventArgs e) => SelectMode(AppOperationMode.Gaming);
    private void OnBalancedClick(object sender, RoutedEventArgs e) => SelectMode(AppOperationMode.Balanced);
    private void OnAutoClick(object sender, RoutedEventArgs e) => SelectMode(AppOperationMode.Auto);
    private void OnSecurityClick(object sender, RoutedEventArgs e) => SelectMode(AppOperationMode.Security);

    private void SelectMode(AppOperationMode mode)
    {
        SelectedMode = mode;
        if (ModeSelectedCommand?.CanExecute(mode) == true)
        {
            ModeSelectedCommand.Execute(mode);
        }
    }

    private static int GetModeIndex(AppOperationMode mode) => mode switch
    {
        AppOperationMode.HighSpeed => 0,
        AppOperationMode.Gaming => 1,
        AppOperationMode.Balanced => 2,
        AppOperationMode.Auto => 3,
        AppOperationMode.Security => 4,
        _ => 2,
    };

    private static Color GetModeColor(AppOperationMode mode) => mode switch
    {
        AppOperationMode.HighSpeed => ColorHighSpeed,
        AppOperationMode.Gaming => ColorGaming,
        AppOperationMode.Balanced => ColorBalanced,
        AppOperationMode.Auto => ColorAuto,
        AppOperationMode.Security => ColorSecurity,
        _ => ColorBalanced,
    };

    private void UpdateThumbPosition(bool animate)
    {
        var totalWidth = TrackGrid.ActualWidth;
        if (totalWidth <= 0)
        {
            return;
        }

        var slotWidth = totalWidth / 5.0;
        var targetX = GetModeIndex(SelectedMode) * slotWidth;

        if (!animate)
        {
            ActiveThumbTransform.BeginAnimation(TranslateTransform.XProperty, null);
            ActiveThumbTransform.X = targetX;
            return;
        }

        var anim = new DoubleAnimation
        {
            To = targetX,
            Duration = TimeSpan.FromMilliseconds(220),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        ActiveThumbTransform.BeginAnimation(TranslateTransform.XProperty, anim);
    }

    private sealed record ModeBrushSet(SolidColorBrush Accent, SolidColorBrush ThumbBg, SolidColorBrush ThumbBorder);

    private static readonly Dictionary<AppOperationMode, ModeBrushSet> FrozenBrushSets = new()
    {
        [AppOperationMode.HighSpeed] = CreateModeBrushSet(ColorHighSpeed),
        [AppOperationMode.Gaming] = CreateModeBrushSet(ColorGaming),
        [AppOperationMode.Balanced] = CreateModeBrushSet(ColorBalanced),
        [AppOperationMode.Auto] = CreateModeBrushSet(ColorAuto),
        [AppOperationMode.Security] = CreateModeBrushSet(ColorSecurity),
    };

    private static ModeBrushSet CreateModeBrushSet(Color accent)
    {
        var accentBrush = new SolidColorBrush(accent);
        accentBrush.Freeze();
        var thumbBg = new SolidColorBrush(Color.FromArgb(0x2A, accent.R, accent.G, accent.B));
        thumbBg.Freeze();
        var thumbBorder = new SolidColorBrush(Color.FromArgb(0xDD, accent.R, accent.G, accent.B));
        thumbBorder.Freeze();
        return new ModeBrushSet(accentBrush, thumbBg, thumbBorder);
    }

    private static ModeBrushSet GetBrushSet(AppOperationMode mode) =>
        FrozenBrushSets.TryGetValue(mode, out var set) ? set : FrozenBrushSets[AppOperationMode.Balanced];

    private void UpdateVisuals()
    {
        var activeMode = SelectedMode;
        var accent = GetModeColor(activeMode);
        var activeBrushes = GetBrushSet(activeMode);

        ActiveThumb.Background = activeBrushes.ThumbBg;
        ActiveThumb.BorderBrush = activeBrushes.ThumbBorder;
        ActivePulseOverlay.Background = activeBrushes.Accent;
        ActiveTopLed.Background = activeBrushes.Accent;

        // In Gaming / MinimizeVisualEffects mode, skip GPU DropShadowEffect shader passes
        // and rely strictly on lightweight opacity & border pulsing for zero FPS impact.
        if (MinimizeVisualEffects)
        {
            ActiveThumb.Effect = null;
        }
        else
        {
            _thumbGlow ??= new DropShadowEffect
            {
                ShadowDepth = 0,
                BlurRadius = 14,
                Opacity = 0.45,
            };
            _thumbGlow.Color = accent;
            ActiveThumb.Effect = _thumbGlow;
        }

        var secondaryText = TryFindResource("Brush.TextSecondary") as Brush ?? Brushes.Gray;
        var primaryText = TryFindResource("Brush.TextPrimary") as Brush ?? Brushes.White;

        ApplySegmentVisual(AppOperationMode.HighSpeed, IconHighSpeed, LabelHighSpeed, DotHighSpeed, activeMode, primaryText, secondaryText);
        ApplySegmentVisual(AppOperationMode.Gaming, IconGaming, LabelGaming, DotGaming, activeMode, primaryText, secondaryText);
        ApplySegmentVisual(AppOperationMode.Balanced, IconBalanced, LabelBalanced, DotBalanced, activeMode, primaryText, secondaryText);
        ApplySegmentVisual(AppOperationMode.Auto, IconAuto, LabelAuto, DotAuto, activeMode, primaryText, secondaryText);
        ApplySegmentVisual(AppOperationMode.Security, IconSecurity, LabelSecurity, DotSecurity, activeMode, primaryText, secondaryText);
    }

    private void ApplySegmentVisual(
        AppOperationMode segmentMode,
        TextBlock icon,
        TextBlock label,
        Ellipse dot,
        AppOperationMode activeMode,
        Brush primaryText,
        Brush secondaryText)
    {
        var isActive = segmentMode == activeMode;
        var isAutoTarget = activeMode == AppOperationMode.Auto
            && segmentMode != AppOperationMode.Auto
            && segmentMode == EffectiveMode;

        if (isActive)
        {
            icon.Foreground = GetBrushSet(segmentMode).Accent;
            label.Foreground = primaryText;
            label.FontWeight = FontWeights.Bold;
            dot.Opacity = 1.0;
        }
        else if (isAutoTarget)
        {
            icon.Foreground = GetBrushSet(segmentMode).Accent;
            label.Foreground = primaryText;
            label.FontWeight = FontWeights.SemiBold;
            dot.Opacity = 0.75;
        }
        else
        {
            icon.Foreground = secondaryText;
            label.Foreground = secondaryText;
            label.FontWeight = FontWeights.Medium;
            dot.Opacity = 0.25;
        }
    }

    /// <summary>
    /// Advances the luminous blinking pulse on the currently selected mode switch.
    /// Safe and ultra-cheap even in Gaming mode (pure opacity modulation without GPU blur shaders).
    /// </summary>
    public void StepPulse(double elapsedSeconds)
    {
        _lastPulsePhase = elapsedSeconds;
        // Smooth luminous heartbeat/blink cycle (~1.8 seconds per cycle)
        var wave = 0.5 + (0.5 * Math.Sin(elapsedSeconds * 3.5));

        ActivePulseOverlay.Opacity = MinimizeVisualEffects
            ? 0.06 + (0.14 * wave)
            : 0.08 + (0.24 * wave);
        ActiveTopLed.Opacity = 0.40 + (0.60 * wave);

        if (_thumbGlow is not null && !MinimizeVisualEffects)
        {
            _thumbGlow.Opacity = 0.20 + (0.55 * wave);
        }

        var activeDot = SelectedMode switch
        {
            AppOperationMode.HighSpeed => DotHighSpeed,
            AppOperationMode.Gaming => DotGaming,
            AppOperationMode.Balanced => DotBalanced,
            AppOperationMode.Auto => DotAuto,
            AppOperationMode.Security => DotSecurity,
            _ => DotBalanced,
        };
        activeDot.Opacity = 0.30 + (0.70 * wave);
    }
}

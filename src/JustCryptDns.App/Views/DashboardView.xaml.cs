using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using JustCryptDns.App.Controls;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Models;
using Microsoft.Win32;

namespace JustCryptDns.App.Views;

public partial class DashboardView : UserControl
{
    private readonly DispatcherTimer _frameTimer;
    private long _lastFrameTimestamp;
    private double _pulseTime;
    private double _lowPowerGaugeAccum;
    private bool _wasEngineRunning;
    private Window? _hostWindow;
    private DashboardViewModel? _attachedVm;
    private bool _isSessionLocked;
    private bool _isSessionHooked;

    public DashboardView()
    {
        InitializeComponent();

        _frameTimer = new DispatcherTimer(DispatcherPriority.Render, Dispatcher)
        {
            Interval = TimeSpan.FromMilliseconds(33),
        };
        _frameTimer.Tick += OnFrameTick;

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        IsVisibleChanged += OnViewVisibilityChanged;
        DataContextChanged += OnDataContextChanged;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        AttachWindow(Window.GetWindow(this));
        AttachViewModel(DataContext as DashboardViewModel);

        if (!_isSessionHooked)
        {
            SystemEvents.SessionSwitch += OnSessionSwitch;
            _isSessionHooked = true;
        }

        UpdateMotionState();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        StopFrameTimer();
        ApplyStatusPulseFrame(reset: true);
        DetachWindow();

        if (_isSessionHooked)
        {
            SystemEvents.SessionSwitch -= OnSessionSwitch;
            _isSessionHooked = false;
        }

        _attachedVm?.SetLiveTelemetryActive(false);
        DetachViewModel();
    }

    private void OnViewVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e) => UpdateMotionState();

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (IsLoaded)
        {
            AttachViewModel(e.NewValue as DashboardViewModel);
            UpdateMotionState();
        }
    }

    private void AttachWindow(Window? window)
    {
        if (ReferenceEquals(_hostWindow, window))
        {
            return;
        }

        DetachWindow();
        _hostWindow = window;
        if (_hostWindow is null)
        {
            return;
        }

        _hostWindow.StateChanged += OnHostStateChanged;
        _hostWindow.IsVisibleChanged += OnHostVisibilityChanged;
    }

    private void DetachWindow()
    {
        if (_hostWindow is null)
        {
            return;
        }

        _hostWindow.StateChanged -= OnHostStateChanged;
        _hostWindow.IsVisibleChanged -= OnHostVisibilityChanged;
        _hostWindow = null;
    }

    private void AttachViewModel(DashboardViewModel? vm)
    {
        if (ReferenceEquals(_attachedVm, vm))
        {
            return;
        }

        DetachViewModel();
        _attachedVm = vm;
        if (_attachedVm is null)
        {
            return;
        }

        _wasEngineRunning = _attachedVm.IsEngineRunning;
        _attachedVm.PropertyChanged += OnViewModelPropertyChanged;
        _attachedVm.TelemetrySampleArrived += OnTelemetrySampleArrived;
        TelemetryWave.SetSamples(_attachedVm.GetInitialTelemetrySamples());

        if (IsLoaded)
        {
            ApplyStatusPulseFrame(reset: false);
        }
    }

    private void DetachViewModel()
    {
        if (_attachedVm is null)
        {
            return;
        }

        _attachedVm.PropertyChanged -= OnViewModelPropertyChanged;
        _attachedVm.TelemetrySampleArrived -= OnTelemetrySampleArrived;
        _attachedVm = null;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_attachedVm is null)
        {
            return;
        }

        if (string.IsNullOrEmpty(e.PropertyName)
            || e.PropertyName is nameof(DashboardViewModel.IsEngineRunning)
                or nameof(DashboardViewModel.EngineState)
                or nameof(DashboardViewModel.StatusPulseStyle)
                or nameof(DashboardViewModel.MinimizeVisualEffects))
        {
            var nowRunning = _attachedVm.IsEngineRunning;
            if (nowRunning && !_wasEngineRunning && IsLoaded && !_attachedVm.MinimizeVisualEffects)
            {
                TriggerAllGaugesIgnitionSweep();
            }

            _wasEngineRunning = nowRunning;
            _frameTimer.Interval = _attachedVm.MinimizeVisualEffects
                ? TimeSpan.FromMilliseconds(66)
                : TimeSpan.FromMilliseconds(33);
            ApplyStatusPulseFrame(reset: !_frameTimer.IsEnabled);
        }
    }

    private void OnHostStateChanged(object? sender, EventArgs e) => UpdateMotionState();

    private void OnHostVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e) => UpdateMotionState();

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        _isSessionLocked = e.Reason == SessionSwitchReason.SessionLock;
        Dispatcher.BeginInvoke(UpdateMotionState);
    }

    private void OnTelemetrySampleArrived(object? sender, NetworkTelemetrySample sample)
    {
        TelemetryWave.AddSample(sample);
    }

    private void UpdateMotionState()
    {
        var shouldRun = IsLoaded
            && IsVisible
            && !_isSessionLocked
            && _hostWindow is not null
            && _hostWindow.IsVisible
            && _hostWindow.WindowState != WindowState.Minimized;

        _attachedVm?.SetLiveTelemetryActive(shouldRun);

        if (shouldRun)
        {
            if (!_frameTimer.IsEnabled)
            {
                _lastFrameTimestamp = Stopwatch.GetTimestamp();
                _frameTimer.Start();
            }

            ApplyStatusPulseFrame(reset: false);
        }
        else
        {
            StopFrameTimer();
            ApplyStatusPulseFrame(reset: true);
        }
    }

    private void StopFrameTimer()
    {
        if (_frameTimer.IsEnabled)
        {
            _frameTimer.Stop();
        }
    }

    private void TriggerAllGaugesIgnitionSweep()
    {
        LatencyGauge.TriggerIgnitionSweep();
        QueriesGauge.TriggerIgnitionSweep();
        BlockedGauge.TriggerIgnitionSweep();
        CacheHitGauge.TriggerIgnitionSweep();
        StabilityGauge.TriggerIgnitionSweep();
    }

    private void ApplyStatusPulseFrame(bool reset)
    {
        var style = _attachedVm?.StatusPulseStyle ?? StatusPulseStyle.Breathing;
        var running = _attachedVm?.IsEngineRunning ?? false;

        var activeColor = TryFindResource(running ? "Brush.Success" : "Brush.Danger") is SolidColorBrush scb
            ? scb.Color
            : (running ? Color.FromRgb(0x3D, 0xD6, 0x8C) : Color.FromRgb(0xFF, 0x6B, 0x6B));

        var disabled = reset || style == StatusPulseStyle.Off;
        var frame = disabled
            ? StatusPulseMath.Evaluate(StatusPulseStyle.Off, 0.0)
            : StatusPulseMath.Evaluate(style, _pulseTime);

        ShieldHaloRing.Opacity = frame.HaloOpacity;
        ShieldHaloScale.ScaleX = frame.HaloScale;
        ShieldHaloScale.ScaleY = frame.HaloScale;
        ShieldBadge.Opacity = frame.SurfaceOpacity;
        ShieldGlowEffect.Color = activeColor;
        ShieldGlowEffect.Opacity = disabled ? 0.0 : 0.25 + (0.65 * frame.Intensity);

        EngineButtonHalo.Opacity = frame.HaloOpacity;
        EngineButtonHaloScale.ScaleX = 1.0 + ((frame.HaloScale - 1.0) * 0.25);
        EngineButtonHaloScale.ScaleY = 1.0 + ((frame.HaloScale - 1.0) * 0.55);
        ToggleEngineButton.Opacity = frame.SurfaceOpacity;
        EngineButtonGlow.Color = activeColor;
        EngineButtonGlow.Opacity = disabled ? 0.0 : 0.20 + (0.65 * frame.Intensity);
    }

    private void OnFrameTick(object? sender, EventArgs e)
    {
        var now = Stopwatch.GetTimestamp();
        var dt = Math.Clamp((now - _lastFrameTimestamp) / (double)Stopwatch.Frequency, 0.005, 0.15);
        _lastFrameTimestamp = now;
        _pulseTime += dt;

        // Always keep the active 5-mode switch blinking smoothly (shader-free in Gaming mode).
        ModeSwitcher.StepPulse(_pulseTime);

        var lowOverhead = _attachedVm?.MinimizeVisualEffects == true;
        if (lowOverhead)
        {
            _lowPowerGaugeAccum += dt;
            if (_lowPowerGaugeAccum < 0.25)
            {
                return;
            }

            var steppedDt = _lowPowerGaugeAccum;
            _lowPowerGaugeAccum = 0;
            LatencyGauge.StepFrame(steppedDt);
            QueriesGauge.StepFrame(steppedDt);
            BlockedGauge.StepFrame(steppedDt);
            CacheHitGauge.StepFrame(steppedDt);
            StabilityGauge.StepFrame(steppedDt);
            TelemetryWave.StepFrame(steppedDt);
            ApplyStatusPulseFrame(reset: true);
            return;
        }

        LatencyGauge.StepFrame(dt);
        QueriesGauge.StepFrame(dt);
        BlockedGauge.StepFrame(dt);
        CacheHitGauge.StepFrame(dt);
        StabilityGauge.StepFrame(dt);
        TelemetryWave.StepFrame(dt);
        ApplyStatusPulseFrame(reset: false);
    }
}

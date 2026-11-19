using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Models;
using Microsoft.Win32;

namespace JustCryptDns.App.Views;

public partial class DashboardView : UserControl
{
    private readonly DispatcherTimer _frameTimer;
    private long _lastFrameTimestamp;
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

        _attachedVm.TelemetrySampleArrived += OnTelemetrySampleArrived;
        TelemetryWave.SetSamples(_attachedVm.GetInitialTelemetrySamples());
    }

    private void DetachViewModel()
    {
        if (_attachedVm is null)
        {
            return;
        }

        _attachedVm.TelemetrySampleArrived -= OnTelemetrySampleArrived;
        _attachedVm = null;
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
        }
        else
        {
            StopFrameTimer();
        }
    }

    private void StopFrameTimer()
    {
        if (_frameTimer.IsEnabled)
        {
            _frameTimer.Stop();
        }
    }

    private void OnFrameTick(object? sender, EventArgs e)
    {
        var now = Stopwatch.GetTimestamp();
        var dt = Math.Clamp((now - _lastFrameTimestamp) / (double)Stopwatch.Frequency, 0.005, 0.1);
        _lastFrameTimestamp = now;

        LatencyGauge.StepFrame(dt);
        QueriesGauge.StepFrame(dt);
        BlockedGauge.StepFrame(dt);
        CacheHitGauge.StepFrame(dt);
        TelemetryWave.StepFrame(dt);
    }
}

using System.Diagnostics;
using System.IO;
using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public sealed partial class SettingsViewModel : PageViewModel
{
    private readonly ISettingsService _settings;
    private readonly INavigationService _navigation;
    private readonly IStartupService _startup;
    private readonly IServiceClient _serviceClient;
    private readonly IProcessPerformanceService? _performance;
    private readonly ILogger<SettingsViewModel> _logger;
    private readonly SynchronizationContext? _ui;
    private bool _loading;

    [ObservableProperty] private string _selectedLanguage = LanguageCodes.System;
    [ObservableProperty] private AppTheme _theme;
    [ObservableProperty] private bool _startWithWindows;
    [ObservableProperty] private bool _startMinimized;
    [ObservableProperty] private bool _autoStartDnsEngine;
    [ObservableProperty] private bool _restorePreviousProfile;
    [ObservableProperty] private bool _enableGamingModeOnStartup;
    [ObservableProperty] private CloseBehavior _closeBehavior;
    [ObservableProperty] private MonitoringMode _monitoringMode = MonitoringMode.Balanced;
    [ObservableProperty] private bool _enablePerformanceDiagnostics;
    [ObservableProperty] private ProcessPerformanceSnapshot? _performanceSnapshot;
    [ObservableProperty] private ServiceConnectionState _serviceState;
    [ObservableProperty] private string? _serviceVersion;

    /// <summary>Raw error detail from the last failed save (displayed through a localized template).</summary>
    [ObservableProperty]
    private string? _saveError;

    public SettingsViewModel(
        ISettingsService settings,
        INavigationService navigation,
        IStartupService startup,
        IServiceClient serviceClient,
        IAppPaths paths,
        ILogger<SettingsViewModel> logger,
        IProcessPerformanceService? performance = null)
        : base("Nav_Settings", "Page_Settings_Subtitle")
    {
        _settings = settings;
        _navigation = navigation;
        _startup = startup;
        _serviceClient = serviceClient;
        _performance = performance;
        _logger = logger;
        _ui = SynchronizationContext.Current;

        LoadFrom(settings.Current);
        UpdateServiceState();
        RefreshPerformance();

        DataFolder = paths.DataDirectory;
        LogsFolder = paths.LogsDirectory;
        Version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.0.0";
        OperatingSystemName = WindowsVersion.DisplayName;
        ShowLoadWarning = settings.LoadOutcome == SettingsLoadOutcome.ResetAfterCorruption;
    }

    public IReadOnlyList<string> Languages => LanguageCodes.All;

    public string Version { get; }

    public string OperatingSystemName { get; }

    public string DataFolder { get; }

    public string LogsFolder { get; }

    public bool ShowLoadWarning { get; }

    public override void OnNavigatedTo()
    {
        _settings.SaveFailed += OnSaveFailed;
        _settings.Changed += OnSettingsChanged;
        _serviceClient.StateChanged += OnServiceStateChanged;
        _ = CheckServiceCommand.ExecuteAsync(null);
    }

    public override void OnNavigatedFrom()
    {
        _settings.SaveFailed -= OnSaveFailed;
        _settings.Changed -= OnSettingsChanged;
        _serviceClient.StateChanged -= OnServiceStateChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _settings.SaveFailed -= OnSaveFailed;
            _settings.Changed -= OnSettingsChanged;
            _serviceClient.StateChanged -= OnServiceStateChanged;
        }

        base.Dispose(disposing);
    }

    partial void OnSelectedLanguageChanged(string value)
    {
        if (!_loading && LanguageCodes.IsSupported(value))
        {
            _ = SaveAsync(s => s.General.Language = value);
        }
    }

    partial void OnThemeChanged(AppTheme value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.Appearance.Theme = value);
        }
    }

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (_loading)
        {
            return;
        }

        ApplyStartupRegistration(value, StartMinimized);
        _ = SaveAsync(s => s.General.StartWithWindows = value);
    }

    partial void OnStartMinimizedChanged(bool value)
    {
        if (_loading)
        {
            return;
        }

        if (StartWithWindows)
        {
            ApplyStartupRegistration(true, value);
        }

        _ = SaveAsync(s => s.General.StartMinimized = value);
    }

    partial void OnAutoStartDnsEngineChanged(bool value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.General.AutoStartDnsEngine = value);
        }
    }

    partial void OnRestorePreviousProfileChanged(bool value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.General.RestorePreviousProfile = value);
        }
    }

    partial void OnEnableGamingModeOnStartupChanged(bool value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.General.EnableGamingModeOnStartup = value);
        }
    }

    partial void OnCloseBehaviorChanged(CloseBehavior value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.General.CloseBehavior = value);
        }
    }

    partial void OnMonitoringModeChanged(MonitoringMode value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.Performance.MonitoringMode = value);
            RefreshPerformance();
        }
    }

    partial void OnEnablePerformanceDiagnosticsChanged(bool value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.Performance.EnablePerformanceDiagnostics = value);
            if (value)
            {
                RefreshPerformance();
            }
        }
    }

    [RelayCommand]
    private void RefreshPerformance()
    {
        if (_performance is not null)
        {
            PerformanceSnapshot = _performance.CaptureSnapshot();
        }
    }

    [RelayCommand]
    private void TrimMemory()
    {
        if (_performance is not null)
        {
            PerformanceSnapshot = _performance.TrimWorkingSet();
        }
    }

    [RelayCommand]
    private void OpenAppearance() => _navigation.Navigate(PageKeys.Appearance);

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CheckServiceAsync()
    {
        await _serviceClient.RefreshStatusAsync();
        UpdateServiceState();
    }

    [RelayCommand]
    private void OpenFolder(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _logger.LogWarning(ex, "Could not open folder {Path}", path);
        }
    }

    private void LoadFrom(AppSettings current)
    {
        _loading = true;
        try
        {
            SelectedLanguage = current.General.Language;
            Theme = current.Appearance.Theme;
            StartWithWindows = current.General.StartWithWindows || _startup.IsRegistered();
            StartMinimized = current.General.StartMinimized;
            AutoStartDnsEngine = current.General.AutoStartDnsEngine;
            RestorePreviousProfile = current.General.RestorePreviousProfile;
            EnableGamingModeOnStartup = current.General.EnableGamingModeOnStartup;
            CloseBehavior = current.General.CloseBehavior;
            MonitoringMode = current.Performance.MonitoringMode;
            EnablePerformanceDiagnostics = current.Performance.EnablePerformanceDiagnostics;
        }
        finally
        {
            _loading = false;
        }
    }

    private void ApplyStartupRegistration(bool enabled, bool minimized)
    {
        try
        {
            _startup.SetRegistration(enabled, minimized);
            SaveError = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _logger.LogError(ex, "Failed to update Windows startup registration.");
            SaveError = ex.Message;
        }
    }

    private void UpdateServiceState()
    {
        ServiceState = _serviceClient.ConnectionState;
        ServiceVersion = _serviceClient.LastStatus?.ServiceVersion;
    }

    private void OnServiceStateChanged(object? sender, EventArgs e)
    {
        if (_ui is not null)
        {
            _ui.Post(_ => UpdateServiceState(), null);
        }
        else
        {
            UpdateServiceState();
        }
    }

    private void OnSettingsChanged(object? sender, AppSettings settings)
    {
        if (settings.General.CloseBehavior != CloseBehavior)
        {
            _loading = true;
            CloseBehavior = settings.General.CloseBehavior;
            _loading = false;
        }
    }

    private void OnSaveFailed(object? sender, Exception ex) => SaveError = ex.Message;

    private async Task SaveAsync(Action<AppSettings> mutate)
    {
        try
        {
            await _settings.UpdateAsync(mutate);
            SaveError = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _logger.LogError(ex, "Saving settings failed.");
            SaveError = ex.Message;
        }
    }
}

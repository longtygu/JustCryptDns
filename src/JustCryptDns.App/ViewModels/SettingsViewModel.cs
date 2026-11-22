using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Controls;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
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
    private readonly IUpdateService? _updateService;
    private readonly IAboutWindowService? _aboutWindow;
    private readonly IAppLifecycleService? _lifecycle;
    private readonly ILogger<SettingsViewModel> _logger;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _downloadCts;
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

    // Software Updates
    [ObservableProperty] private bool _autoCheckForUpdates = true;
    [ObservableProperty] private bool _includePrereleases;
    [ObservableProperty] private UpdateCheckStatus _updateStatus = UpdateCheckStatus.Idle;
    [ObservableProperty] private string _updateStatusMessage = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDownloadUpdate))]
    [NotifyPropertyChangedFor(nameof(ShowDownloadButton))]
    [NotifyPropertyChangedFor(nameof(ReleaseHeaderText))]
    [NotifyPropertyChangedFor(nameof(ReleaseMetaText))]
    [NotifyPropertyChangedFor(nameof(ReleaseNotesDisplay))]
    private UpdateReleaseInfo? _latestRelease;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowDownloadButton))]
    private bool _hasUpdateAvailable;

    [ObservableProperty] private bool _isCheckingUpdates;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDownloadUpdate))]
    [NotifyPropertyChangedFor(nameof(ShowDownloadButton))]
    private bool _isDownloadingUpdate;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDownloadUpdate))]
    [NotifyPropertyChangedFor(nameof(ShowDownloadButton))]
    private bool _isUpdateReadyToInstall;

    [ObservableProperty] private bool _showDownloadChart;
    [ObservableProperty] private double _downloadPercent;
    [ObservableProperty] private string _downloadSpeedText = "0 KB/s";
    [ObservableProperty] private string _downloadTransferredText = "0.0 / 0.0 MB";
    [ObservableProperty] private string _downloadEtaText = "--";
    [ObservableProperty] private string? _downloadError;
    [ObservableProperty] private string? _checksumStatusText;
    [ObservableProperty] private PreparedUpdatePackage? _preparedPackage;
    [ObservableProperty] private string _lastCheckedText = "--";

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
        IProcessPerformanceService? performance = null,
        IUpdateService? updateService = null,
        IAboutWindowService? aboutWindow = null,
        IAppLifecycleService? lifecycle = null)
        : base("Nav_Settings", "Page_Settings_Subtitle")
    {
        _settings = settings;
        _navigation = navigation;
        _startup = startup;
        _serviceClient = serviceClient;
        _performance = performance;
        _updateService = updateService;
        _aboutWindow = aboutWindow;
        _lifecycle = lifecycle;
        _logger = logger;
        _ui = SynchronizationContext.Current;

        LoadFrom(settings.Current);
        UpdateServiceState();
        RefreshPerformance();

        DataFolder = paths.DataDirectory;
        LogsFolder = paths.LogsDirectory;
        Version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "1.7.1";
        OperatingSystemName = WindowsVersion.DisplayName;
        ShowLoadWarning = settings.LoadOutcome is SettingsLoadOutcome.ResetAfterCorruption or SettingsLoadOutcome.NewerSchemaReadOnly;
        RefreshUpdateSummaryFromService();
    }

    public IReadOnlyList<string> Languages => LanguageCodes.All;

    public string Version { get; }

    public string OperatingSystemName { get; }

    public string DataFolder { get; }

    public string LogsFolder { get; }

    public bool ShowLoadWarning { get; }

    public string CurrentAppVersion => _updateService?.CurrentVersion ?? Version;

    public bool CanDownloadUpdate => LatestRelease?.PreferredAsset is not null && !IsDownloadingUpdate && !IsUpdateReadyToInstall;

    public bool ShowDownloadButton => HasUpdateAvailable && CanDownloadUpdate;

    public string ReleaseHeaderText => LatestRelease?.Name ?? string.Empty;

    public string ReleaseMetaText
    {
        get
        {
            if (LatestRelease is null)
            {
                return string.Empty;
            }

            var sizeMb = LatestRelease.PreferredAsset is { SizeBytes: > 0 } asset
                ? $"{asset.SizeBytes / (1024.0 * 1024.0):0.0} MB"
                : "--";
            var dateStr = LatestRelease.PublishedAtUtc.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.CurrentCulture);
            return $"{LatestRelease.TagName}  •  {dateStr}  •  {sizeMb}";
        }
    }

    public string ReleaseNotesDisplay =>
        string.IsNullOrWhiteSpace(LatestRelease?.ReleaseNotes)
            ? LocalizationManager.Instance["Settings_Updates_NoNotes"]
            : LatestRelease!.ReleaseNotes;

    public event EventHandler<UpdateDownloadProgress>? DownloadProgressReceived;

    public event EventHandler? DownloadChartResetRequested;

    public override void OnNavigatedTo()
    {
        _settings.SaveFailed += OnSaveFailed;
        _settings.Changed += OnSettingsChanged;
        _serviceClient.StateChanged += OnServiceStateChanged;
        if (_updateService is not null)
        {
            _updateService.UpdateCheckCompleted += OnUpdateCheckCompleted;
        }

        RefreshUpdateSummaryFromService();
        _ = CheckServiceCommand.ExecuteAsync(null);
    }

    public override void OnNavigatedFrom()
    {
        _settings.SaveFailed -= OnSaveFailed;
        _settings.Changed -= OnSettingsChanged;
        _serviceClient.StateChanged -= OnServiceStateChanged;
        if (_updateService is not null)
        {
            _updateService.UpdateCheckCompleted -= OnUpdateCheckCompleted;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _settings.SaveFailed -= OnSaveFailed;
            _settings.Changed -= OnSettingsChanged;
            _serviceClient.StateChanged -= OnServiceStateChanged;
            if (_updateService is not null)
            {
                _updateService.UpdateCheckCompleted -= OnUpdateCheckCompleted;
            }

            _downloadCts?.Cancel();
            _downloadCts?.Dispose();
            _downloadCts = null;
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

    partial void OnAutoCheckForUpdatesChanged(bool value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.Updates.AutoCheckOnStartup = value);
        }
    }

    partial void OnIncludePrereleasesChanged(bool value)
    {
        if (!_loading)
        {
            _ = SaveAsync(s => s.Updates.IncludePrereleases = value);
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

    [RelayCommand]
    private void OpenAboutWindow() => _aboutWindow?.Show(AboutWindowTab.Overview);

    [RelayCommand]
    private void OpenBugReport() => _aboutWindow?.Show(AboutWindowTab.BugReport);

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CheckForUpdatesAsync()
    {
        if (_updateService is null)
        {
            return;
        }

        IsCheckingUpdates = true;
        UpdateStatus = UpdateCheckStatus.Checking;
        UpdateStatusMessage = LocalizationManager.Instance["Settings_Updates_Checking"];
        try
        {
            var result = await _updateService.CheckForUpdatesAsync(IncludePrereleases);
            ApplyUpdateCheckResult(result);
        }
        finally
        {
            IsCheckingUpdates = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task DownloadUpdateAsync()
    {
        if (_updateService is null || LatestRelease?.PreferredAsset is null || IsDownloadingUpdate)
        {
            return;
        }

        _downloadCts?.Cancel();
        _downloadCts?.Dispose();
        _downloadCts = new CancellationTokenSource();

        DownloadError = null;
        ChecksumStatusText = null;
        PreparedPackage = null;
        IsUpdateReadyToInstall = false;
        ShowDownloadChart = true;
        IsDownloadingUpdate = true;
        DownloadPercent = 0;
        DownloadSpeedText = "0 KB/s";
        DownloadTransferredText = "0.0 / -- MB";
        DownloadEtaText = "--";
        DownloadChartResetRequested?.Invoke(this, EventArgs.Empty);

        var progress = new Progress<UpdateDownloadProgress>(OnDownloadProgress);
        try
        {
            var prepared = await _updateService.DownloadAndPrepareAsync(LatestRelease, progress, _downloadCts.Token);
            PreparedPackage = prepared;
            IsUpdateReadyToInstall = true;
            DownloadPercent = 100;
            ChecksumStatusText = prepared.ChecksumVerified && prepared.ActualSha256 is { Length: >= 12 }
                ? string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Settings_Updates_ChecksumOk"], prepared.ActualSha256[..12])
                : LocalizationManager.Instance["Settings_Updates_ChecksumSkipped"];
        }
        catch (OperationCanceledException)
        {
            DownloadError = LocalizationManager.Instance["Settings_Updates_DownloadCancelled"];
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Downloading update failed.");
            DownloadError = ex.Message;
        }
        finally
        {
            IsDownloadingUpdate = false;
        }
    }

    [RelayCommand]
    private void CancelDownload() => _downloadCts?.Cancel();

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task InstallUpdateNowAsync()
    {
        if (_updateService is null || _lifecycle is null || PreparedPackage is null)
        {
            return;
        }

        DownloadError = null;
        var (launched, err) = await _lifecycle.ApplyUpdateAndRestartAsync(() =>
        {
            var ok = _updateService.LaunchPreparedUpdate(PreparedPackage, out var launchErr);
            return (ok, launchErr);
        });

        if (!launched)
        {
            DownloadError = err;
        }
    }

    [RelayCommand]
    private void OpenReleaseOnGitHub()
    {
        var rawUrl = LatestRelease?.HtmlUrl;
        var url = !string.IsNullOrWhiteSpace(rawUrl)
            && Uri.TryCreate(rawUrl.Trim(), UriKind.Absolute, out var parsed)
            && string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            ? parsed.AbsoluteUri
            : (BugReportBuilder.GitHubRepoUrl + "/releases");
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _logger.LogWarning(ex, "Could not open release URL {Url}.", url);
        }
    }

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
            AutoCheckForUpdates = current.Updates.AutoCheckOnStartup;
            IncludePrereleases = current.Updates.IncludePrereleases;
            RefreshLastCheckedText(current.Updates.LastCheckedUtc);
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
        void Sync()
        {
            if (settings.General.CloseBehavior != CloseBehavior)
            {
                _loading = true;
                CloseBehavior = settings.General.CloseBehavior;
                _loading = false;
            }
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Sync);
        }
        else
        {
            Sync();
        }
    }

    private void OnSaveFailed(object? sender, Exception ex)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => SaveError = ex.Message);
        }
        else if (_ui is not null)
        {
            _ui.Post(_ => SaveError = ex.Message, null);
        }
        else
        {
            SaveError = ex.Message;
        }
    }

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

    private void RefreshUpdateSummaryFromService()
    {
        if (_updateService?.LatestResult is { } cached)
        {
            ApplyUpdateCheckResult(cached);
        }
        else
        {
            UpdateStatus = UpdateCheckStatus.Idle;
            UpdateStatusMessage = LocalizationManager.Instance["Settings_Updates_IdleHint"];
            HasUpdateAvailable = false;
            RefreshLastCheckedText(_settings.Current.Updates.LastCheckedUtc);
        }
    }

    private void OnUpdateCheckCompleted(object? sender, UpdateCheckResult result)
    {
        if (_ui is not null)
        {
            _ui.Post(_ => ApplyUpdateCheckResult(result), null);
        }
        else
        {
            ApplyUpdateCheckResult(result);
        }
    }

    private void ApplyUpdateCheckResult(UpdateCheckResult result)
    {
        UpdateStatus = result.Status;
        LatestRelease = result.Release;
        HasUpdateAvailable = result.Status == UpdateCheckStatus.UpdateAvailable;
        RefreshLastCheckedText(result.CheckedAtUtc);

        UpdateStatusMessage = result.Status switch
        {
            UpdateCheckStatus.UpdateAvailable when result.Release is not null =>
                string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Settings_Updates_AvailableMsg"], result.Release.Version),
            UpdateCheckStatus.UpToDate =>
                string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Settings_Updates_UpToDateMsg"], CurrentAppVersion),
            UpdateCheckStatus.NoReleasesPublished => LocalizationManager.Instance["Settings_Updates_NoReleasesMsg"],
            UpdateCheckStatus.RateLimited => LocalizationManager.Instance["Settings_Updates_RateLimitedMsg"],
            UpdateCheckStatus.Error => result.ErrorMessage ?? LocalizationManager.Instance["Settings_Updates_ErrorMsg"],
            UpdateCheckStatus.Checking => LocalizationManager.Instance["Settings_Updates_Checking"],
            _ => LocalizationManager.Instance["Settings_Updates_IdleHint"],
        };
    }

    private void RefreshLastCheckedText(DateTimeOffset? checkedUtc)
    {
        LastCheckedText = checkedUtc is { } ts
            ? ts.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture)
            : LocalizationManager.Instance["Settings_Updates_NeverChecked"];
    }

    private void OnDownloadProgress(UpdateDownloadProgress progress)
    {
        DownloadPercent = progress.ProgressPercent;
        DownloadSpeedText = UpdateDownloadChartControl.FormatSpeed(progress.InstantBytesPerSecond);
        var downloadedMb = progress.BytesDownloaded / (1024.0 * 1024.0);
        var totalMb = progress.TotalBytes / (1024.0 * 1024.0);
        DownloadTransferredText = progress.TotalBytes > 0
            ? $"{downloadedMb:0.0} / {totalMb:0.0} MB"
            : $"{downloadedMb:0.0} MB";
        DownloadEtaText = progress.EstimatedRemaining is { TotalSeconds: >= 0 } eta
            ? eta.ToString(@"mm\:ss", CultureInfo.InvariantCulture)
            : "--";

        DownloadProgressReceived?.Invoke(this, progress);
    }
}

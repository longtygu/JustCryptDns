using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public sealed partial class AboutViewModel : ObservableObject, IDisposable
{
    private readonly IAppPaths _paths;
    private readonly IBugDiagnosticsCollector _diagnosticsCollector;
    private readonly INavigationService _navigation;
    private readonly ILogger<AboutViewModel> _logger;
    private BugDiagnosticsSnapshot? _latestSnapshot;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOverviewTab))]
    [NotifyPropertyChangedFor(nameof(IsArchitectureTab))]
    [NotifyPropertyChangedFor(nameof(IsBugReportTab))]
    private int _selectedTabIndex;

    public bool IsOverviewTab => SelectedTabIndex == 0;

    public bool IsArchitectureTab => SelectedTabIndex == 1;

    public bool IsBugReportTab => SelectedTabIndex == 2;

    [ObservableProperty]
    private BugReportCategory _selectedBugCategory = BugReportCategory.DnsEngine;

    [ObservableProperty]
    private string _bugTitle = string.Empty;

    [ObservableProperty]
    private string _bugDescription = string.Empty;

    [ObservableProperty]
    private bool _includeDiagnostics = true;

    [ObservableProperty]
    private string _diagnosticsPreview = string.Empty;

    [ObservableProperty]
    private string? _bugFeedbackMessage;

    [ObservableProperty]
    private bool _isBugFeedbackError;

    public AboutViewModel(
        IAppPaths paths,
        IBugDiagnosticsCollector diagnosticsCollector,
        INavigationService navigation,
        ILogger<AboutViewModel> logger)
    {
        _paths = paths;
        _diagnosticsCollector = diagnosticsCollector;
        _navigation = navigation;
        _logger = logger;

        Version = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
            ?.Split('+')[0] ?? "1.3.0";
        OperatingSystemName = WindowsVersion.DisplayName;
        RefreshDiagnostics();
    }

    public string AuthorName => BugReportBuilder.AuthorName;

    public string AuthorTagline => BugReportBuilder.AuthorTagline;

    public string GitHubUrl => BugReportBuilder.GitHubRepoUrl;

    public string FacebookUrl => BugReportBuilder.AuthorFacebookUrl;

    public string AvatarPackUri => "pack://application:,,,/Resources/AuthorAvatar.jpg";

    public string Version { get; }

    public string OperatingSystemName { get; }

    public IReadOnlyList<BugReportCategory> BugCategories { get; } = Enum.GetValues<BugReportCategory>();

    public void SelectTab(AboutWindowTab tab)
    {
        SelectedTabIndex = (int)tab;
        if (tab == AboutWindowTab.BugReport)
        {
            RefreshDiagnostics();
        }
    }

    partial void OnSelectedBugCategoryChanged(BugReportCategory value) => RebuildDiagnosticsPreview();

    partial void OnBugTitleChanged(string value) => RebuildDiagnosticsPreview();

    partial void OnBugDescriptionChanged(string value) => RebuildDiagnosticsPreview();

    partial void OnIncludeDiagnosticsChanged(bool value) => RebuildDiagnosticsPreview();

    [RelayCommand]
    private void SelectTabByIndex(string? indexText)
    {
        if (int.TryParse(indexText, out var idx) && idx is >= 0 and <= 2)
        {
            SelectTab((AboutWindowTab)idx);
        }
    }

    [RelayCommand]
    private void OpenGitHubRepo() => TryOpenUrl(GitHubUrl);

    [RelayCommand]
    private void OpenAuthorFacebook() => TryOpenUrl(FacebookUrl);

    [RelayCommand]
    private void OpenUpdatesInSettings()
    {
        _navigation.Navigate(PageKeys.Settings);
        if (Application.Current?.MainWindow is { } main)
        {
            if (!main.IsVisible)
            {
                main.Show();
            }

            if (main.WindowState == WindowState.Minimized)
            {
                main.WindowState = WindowState.Normal;
            }

            main.Activate();
        }
    }

    [RelayCommand]
    private void RefreshDiagnostics()
    {
        _latestSnapshot = _diagnosticsCollector.Capture();
        RebuildDiagnosticsPreview();
    }

    [RelayCommand]
    private void CopyDiagnostics()
    {
        _latestSnapshot ??= _diagnosticsCollector.Capture();
        var draft = new BugReportDraft(SelectedBugCategory, BugTitle, BugDescription, IncludeDiagnostics);
        var markdown = BugReportBuilder.BuildGitHubMarkdown(draft, _latestSnapshot);
        TryCopyToClipboard(markdown);
        IsBugFeedbackError = false;
        BugFeedbackMessage = LocalizationManager.Instance["BugReport_Copied"];
    }

    [RelayCommand]
    private void SubmitGitHubIssue()
    {
        if (string.IsNullOrWhiteSpace(BugTitle) && string.IsNullOrWhiteSpace(BugDescription))
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_ValidationEmpty"];
            return;
        }

        _latestSnapshot = _diagnosticsCollector.Capture();
        var draft = new BugReportDraft(SelectedBugCategory, BugTitle, BugDescription, IncludeDiagnostics);
        var fullMarkdown = BugReportBuilder.BuildGitHubMarkdown(draft, _latestSnapshot);
        TryCopyToClipboard(fullMarkdown);

        var url = BugReportBuilder.BuildGitHubIssueUrl(draft, _latestSnapshot);
        if (TryOpenUrl(url))
        {
            IsBugFeedbackError = false;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_GitHubOpened"];
        }
        else
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_OpenUrlFailed"];
        }
    }

    [RelayCommand]
    private void SubmitFacebookReport()
    {
        if (string.IsNullOrWhiteSpace(BugTitle) && string.IsNullOrWhiteSpace(BugDescription))
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_ValidationEmpty"];
            return;
        }

        _latestSnapshot = _diagnosticsCollector.Capture();
        var draft = new BugReportDraft(SelectedBugCategory, BugTitle, BugDescription, IncludeDiagnostics);
        var message = BugReportBuilder.BuildFacebookMessage(draft, _latestSnapshot);
        TryCopyToClipboard(message);

        if (TryOpenUrl(FacebookUrl))
        {
            IsBugFeedbackError = false;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_FacebookOpened"];
        }
        else
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_OpenUrlFailed"];
        }
    }

    [RelayCommand]
    private void OpenLogsFolder()
    {
        try
        {
            Directory.CreateDirectory(_paths.LogsDirectory);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_paths.LogsDirectory}\"") { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _logger.LogWarning(ex, "Could not open logs directory {Path}.", _paths.LogsDirectory);
        }
    }

    public void Dispose()
    {
    }

    private void RebuildDiagnosticsPreview()
    {
        var draft = new BugReportDraft(SelectedBugCategory, BugTitle, BugDescription, IncludeDiagnostics);
        DiagnosticsPreview = BugReportBuilder.BuildGitHubMarkdown(draft, _latestSnapshot);
    }

    private bool TryOpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
            return true;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _logger.LogWarning(ex, "Could not open external URL {Url}.", url);
            return false;
        }
    }

    private void TryCopyToClipboard(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (ExternalException ex)
        {
            _logger.LogWarning(ex, "Clipboard copy failed while preparing bug report.");
        }
    }
}

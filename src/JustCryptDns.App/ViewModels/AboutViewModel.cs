using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media.Imaging;
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
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed record BugReportAttachmentItem(
    string FilePath,
    string FileName,
    string FileSizeText,
    BitmapSource? Thumbnail);

public sealed partial class AboutViewModel : ObservableObject, IDisposable
{
    private const int MaxAttachmentCount = 6;
    private const long MaxAttachmentBytes = 15 * 1024 * 1024;
    private static readonly HashSet<string> SupportedImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif",
    };

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
    private string _generatedGitHubIssueUrl = BugReportBuilder.GitHubNewIssueUrl;

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
            ?.Split('+')[0] ?? "1.5.1";
        OperatingSystemName = WindowsVersion.DisplayName;

        AttachedImages.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasAttachedImages));
            RebuildDiagnosticsPreview();
        };

        RefreshDiagnostics();
    }

    public string AuthorName => BugReportBuilder.AuthorName;

    public string AuthorTagline => BugReportBuilder.AuthorTagline;

    public string GitHubUrl => BugReportBuilder.GitHubRepoUrl;

    public string GitHubNewIssueCleanUrl => BugReportBuilder.GitHubNewIssueUrl;

    public string FacebookUrl => BugReportBuilder.AuthorFacebookUrl;

    public string AvatarPackUri => "pack://application:,,,/JustCryptDns;component/Resources/AuthorAvatar.jpg";

    public string Version { get; }

    public string OperatingSystemName { get; }

    public IReadOnlyList<BugReportCategory> BugCategories { get; } = Enum.GetValues<BugReportCategory>();

    public ObservableCollection<BugReportAttachmentItem> AttachedImages { get; } = [];

    public bool HasAttachedImages => AttachedImages.Count > 0;

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
    private void AttachImages()
    {
        var dialog = new OpenFileDialog
        {
            Title = LocalizationManager.Instance["BugReport_Attach_DialogTitle"],
            Multiselect = true,
            CheckFileExists = true,
            Filter = "Image Files (*.png;*.jpg;*.jpeg;*.webp;*.bmp;*.gif)|*.png;*.jpg;*.jpeg;*.webp;*.bmp;*.gif|All Files (*.*)|*.*",
        };

        if (dialog.ShowDialog() != true || dialog.FileNames.Length == 0)
        {
            return;
        }

        var added = 0;
        var skippedLargeOrLimit = false;
        foreach (var path in dialog.FileNames)
        {
            if (!TryAddImageFile(path, out var reasonLimitOrSize))
            {
                skippedLargeOrLimit |= reasonLimitOrSize;
                continue;
            }

            added++;
        }

        if (added > 0)
        {
            IsBugFeedbackError = false;
            BugFeedbackMessage = LocalizationManager.Instance.Format("BugReport_Attach_Added", added);
        }
        else if (skippedLargeOrLimit)
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_Attach_LimitOrSize"];
        }
    }

    [RelayCommand]
    private void PasteScreenshot()
    {
        try
        {
            if (Clipboard.ContainsImage())
            {
                var image = Clipboard.GetImage();
                if (image is not null)
                {
                    if (AttachedImages.Count >= MaxAttachmentCount)
                    {
                        IsBugFeedbackError = true;
                        BugFeedbackMessage = LocalizationManager.Instance["BugReport_Attach_LimitOrSize"];
                        return;
                    }

                    var dir = EnsureAttachmentsDirectory();
                    var fileName = $"screenshot-{DateTime.Now:yyyyMMdd-HHmmss-fff}.png";
                    var fullPath = Path.Combine(dir, fileName);

                    var encoder = new PngBitmapEncoder();
                    encoder.Frames.Add(BitmapFrame.Create(image));
                    using (var fs = File.Create(fullPath))
                    {
                        encoder.Save(fs);
                    }

                    if (TryAddImageFile(fullPath, out _))
                    {
                        IsBugFeedbackError = false;
                        BugFeedbackMessage = LocalizationManager.Instance.Format("BugReport_Attach_PastedOne", fileName);
                        return;
                    }
                }
            }
            else if (Clipboard.ContainsFileDropList())
            {
                var files = Clipboard.GetFileDropList();
                var added = 0;
                foreach (var f in files)
                {
                    if (!string.IsNullOrWhiteSpace(f) && TryAddImageFile(f, out _))
                    {
                        added++;
                    }
                }

                if (added > 0)
                {
                    IsBugFeedbackError = false;
                    BugFeedbackMessage = LocalizationManager.Instance.Format("BugReport_Attach_Added", added);
                    return;
                }
            }

            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_Attach_NoClipboardImage"];
        }
        catch (Exception ex) when (ex is ExternalException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            _logger.LogWarning(ex, "Could not paste screenshot from clipboard.");
            IsBugFeedbackError = true;
            BugFeedbackMessage = ex.Message;
        }
    }

    [RelayCommand]
    private void RemoveAttachment(BugReportAttachmentItem? item)
    {
        if (item is null)
        {
            return;
        }

        AttachedImages.Remove(item);
    }

    [RelayCommand]
    private void CopyAttachmentsToClipboard()
    {
        var validPaths = AttachedImages
            .Select(a => a.FilePath)
            .Where(File.Exists)
            .ToArray();
        if (validPaths.Length == 0)
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_Attach_NoValidFiles"];
            return;
        }

        try
        {
            var data = new DataObject();
            var dropList = new StringCollection();
            dropList.AddRange(validPaths);
            data.SetFileDropList(dropList);

            // Also place bitmap image on clipboard when 1 file is attached so Ctrl+V works directly in GitHub & Messenger.
            if (validPaths.Length == 1 && TryLoadFullBitmap(validPaths[0]) is { } bmp)
            {
                data.SetImage(bmp);
            }

            Clipboard.SetDataObject(data, true);
            IsBugFeedbackError = false;
            BugFeedbackMessage = LocalizationManager.Instance.Format("BugReport_Attach_CopiedForPaste", validPaths.Length);
        }
        catch (ExternalException ex)
        {
            _logger.LogWarning(ex, "Could not copy attachments to clipboard.");
            IsBugFeedbackError = true;
            BugFeedbackMessage = ex.Message;
        }
    }

    [RelayCommand]
    private void OpenAttachmentsFolder()
    {
        try
        {
            var firstExisting = AttachedImages.Select(a => a.FilePath).FirstOrDefault(File.Exists);
            if (!string.IsNullOrEmpty(firstExisting))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{firstExisting}\"") { UseShellExecute = true })?.Dispose();
                return;
            }

            var dir = EnsureAttachmentsDirectory();
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _logger.LogWarning(ex, "Could not open bug attachments directory.");
        }
    }

    [RelayCommand]
    private void CopyDiagnostics()
    {
        _latestSnapshot ??= _diagnosticsCollector.Capture();
        var draft = BuildCurrentDraft();
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
        var draft = BuildCurrentDraft();
        var fullMarkdown = BugReportBuilder.BuildGitHubMarkdown(draft, _latestSnapshot);
        DiagnosticsPreview = fullMarkdown;
        TryCopyToClipboard(fullMarkdown);

        var url = BugReportBuilder.BuildGitHubIssueUrl(draft, _latestSnapshot);
        GeneratedGitHubIssueUrl = url;

        if (TryOpenUrl(url))
        {
            IsBugFeedbackError = false;
            BugFeedbackMessage = HasAttachedImages
                ? LocalizationManager.Instance.Format("BugReport_GitHubOpenedWithImages", AttachedImages.Count)
                : LocalizationManager.Instance["BugReport_GitHubOpened"];
        }
        else
        {
            IsBugFeedbackError = true;
            BugFeedbackMessage = LocalizationManager.Instance["BugReport_OpenUrlFailed"];
        }
    }

    [RelayCommand]
    private void OpenCleanGitHubIssues()
    {
        _latestSnapshot ??= _diagnosticsCollector.Capture();
        var draft = BuildCurrentDraft();
        var fullMarkdown = BugReportBuilder.BuildGitHubMarkdown(draft, _latestSnapshot);
        DiagnosticsPreview = fullMarkdown;
        TryCopyToClipboard(fullMarkdown);

        if (TryOpenUrl(BugReportBuilder.GitHubNewIssueUrl))
        {
            IsBugFeedbackError = false;
            BugFeedbackMessage = HasAttachedImages
                ? LocalizationManager.Instance.Format("BugReport_GitHubCleanOpenedWithImages", AttachedImages.Count)
                : LocalizationManager.Instance["BugReport_GitHubCleanOpened"];
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
        var draft = BuildCurrentDraft();
        var message = BugReportBuilder.BuildFacebookMessage(draft, _latestSnapshot);
        TryCopyToClipboard(message);

        if (TryOpenUrl(FacebookUrl))
        {
            IsBugFeedbackError = false;
            BugFeedbackMessage = HasAttachedImages
                ? LocalizationManager.Instance.Format("BugReport_FacebookOpenedWithImages", AttachedImages.Count)
                : LocalizationManager.Instance["BugReport_FacebookOpened"];
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

    private BugReportDraft BuildCurrentDraft() => new(
        SelectedBugCategory,
        BugTitle,
        BugDescription,
        IncludeDiagnostics,
        AttachedImages.Select(a => a.FilePath).ToList());

    private void RebuildDiagnosticsPreview()
    {
        var draft = BuildCurrentDraft();
        DiagnosticsPreview = BugReportBuilder.BuildGitHubMarkdown(draft, _latestSnapshot);
        GeneratedGitHubIssueUrl = BugReportBuilder.BuildGitHubIssueUrl(draft, _latestSnapshot);
    }

    private bool TryAddImageFile(string path, out bool rejectedByLimitOrSize)
    {
        rejectedByLimitOrSize = false;
        if (AttachedImages.Count >= MaxAttachmentCount)
        {
            rejectedByLimitOrSize = true;
            return false;
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return false;
        }

        var ext = Path.GetExtension(path);
        if (!SupportedImageExtensions.Contains(ext))
        {
            return false;
        }

        if (AttachedImages.Any(a => string.Equals(a.FilePath, path, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var info = new FileInfo(path);
        if (info.Length == 0 || info.Length > MaxAttachmentBytes)
        {
            rejectedByLimitOrSize = true;
            return false;
        }

        var sizeText = info.Length >= 1024 * 1024
            ? string.Create(CultureInfo.InvariantCulture, $"{info.Length / (1024.0 * 1024.0):0.0} MB")
            : string.Create(CultureInfo.InvariantCulture, $"{Math.Max(1, info.Length / 1024.0):0} KB");

        AttachedImages.Add(new BugReportAttachmentItem(
            path,
            info.Name,
            sizeText,
            TryLoadThumbnail(path)));
        return true;
    }

    private string EnsureAttachmentsDirectory()
    {
        var dir = Path.Combine(_paths.LogsDirectory, "bug-attachments");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static BitmapImage? TryLoadThumbnail(string path)
    {
        try
        {
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.UriSource = new Uri(path, UriKind.Absolute);
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.DecodePixelWidth = 140;
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch
        {
            return null;
        }
    }

    private static BitmapImage? TryLoadFullBitmap(string path)
    {
        try
        {
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.UriSource = new Uri(path, UriKind.Absolute);
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch
        {
            return null;
        }
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

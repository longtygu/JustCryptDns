using System.Diagnostics;
using System.IO;
using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public sealed partial class SettingsViewModel : PageViewModel
{
    private readonly ISettingsService _settings;
    private readonly ILogger<SettingsViewModel> _logger;
    private bool _loading;

    [ObservableProperty]
    private string _selectedLanguage;

    [ObservableProperty]
    private AppTheme _theme;

    /// <summary>Raw error detail from the last failed save (displayed through a localized template).</summary>
    [ObservableProperty]
    private string? _saveError;

    public SettingsViewModel(ISettingsService settings, IAppPaths paths, ILogger<SettingsViewModel> logger)
        : base("Nav_Settings", "Page_Settings_Subtitle")
    {
        _settings = settings;
        _logger = logger;
        _loading = true;
        _selectedLanguage = settings.Current.General.Language;
        _theme = settings.Current.Appearance.Theme;
        _loading = false;

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

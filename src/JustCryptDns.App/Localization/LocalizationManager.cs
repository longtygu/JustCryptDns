using System.ComponentModel;
using System.Globalization;
using System.Resources;
using JustCryptDns.Core.Configuration;

namespace JustCryptDns.App.Localization;

/// <summary>
/// Runtime-switchable string provider. XAML binds to the indexer (via <see cref="LocExtension"/>);
/// changing <see cref="Culture"/> refreshes every bound string without restarting.
/// </summary>
public sealed class LocalizationManager : INotifyPropertyChanged
{
    public const string ResourceBaseName = "JustCryptDns.App.Resources.Strings.Strings";

    private readonly ResourceManager _resources = new(ResourceBaseName, typeof(LocalizationManager).Assembly);
    private CultureInfo _culture = CultureInfo.CurrentUICulture;

    private LocalizationManager()
    {
    }

    public static LocalizationManager Instance { get; } = new();

    /// <summary>The OS UI culture at process start, used for the "system" language option.</summary>
    public static CultureInfo SystemCulture { get; } = CultureInfo.CurrentUICulture;

    public event PropertyChangedEventHandler? PropertyChanged;

    public CultureInfo Culture => _culture;

    public string this[string key] => Get(key);

    public string Get(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return string.Empty;
        }

        return _resources.GetString(key, _culture) ?? $"[{key}]";
    }

    public string Format(string key, params object[] args) => string.Format(_culture, Get(key), args);

    /// <summary>Applies a language code from <see cref="LanguageCodes"/>.</summary>
    public void SetLanguage(string code)
    {
        var culture = ResolveCulture(code);
        if (culture.Name == _culture.Name)
        {
            return;
        }

        _culture = culture;
        CultureInfo.CurrentUICulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Culture)));
    }

    public static CultureInfo ResolveCulture(string code)
    {
        if (string.Equals(code, LanguageCodes.Vietnamese, StringComparison.OrdinalIgnoreCase))
        {
            return CultureInfo.GetCultureInfo("vi-VN");
        }

        if (string.Equals(code, LanguageCodes.English, StringComparison.OrdinalIgnoreCase))
        {
            return CultureInfo.GetCultureInfo("en-US");
        }

        // System: use Vietnamese only if the OS UI language is Vietnamese; otherwise English.
        return SystemCulture.TwoLetterISOLanguageName == "vi"
            ? CultureInfo.GetCultureInfo("vi-VN")
            : CultureInfo.GetCultureInfo("en-US");
    }
}

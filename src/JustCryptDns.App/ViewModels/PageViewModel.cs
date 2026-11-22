using CommunityToolkit.Mvvm.ComponentModel;

namespace JustCryptDns.App.ViewModels;

/// <summary>
/// Base class for pages hosted in the shell. Pages are created on navigation and disposed when left,
/// so background work must be started in <see cref="OnNavigatedTo"/> and stopped in <see cref="OnNavigatedFrom"/>.
/// </summary>
public abstract class PageViewModel : ObservableObject, IDisposable
{
    protected PageViewModel(string titleKey, string subtitleKey)
    {
        TitleKey = titleKey;
        SubtitleKey = subtitleKey;
    }

    /// <summary>Localization key of the page title.</summary>
    public string TitleKey { get; }

    /// <summary>Localization key of the page subtitle.</summary>
    public string SubtitleKey { get; }

    public virtual void OnNavigatedTo()
    {
    }

    public virtual void OnNavigatedFrom()
    {
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
    }
}

/// <summary>Sidebar entry. Label and group are localization keys so the ViewModel holds no UI text.</summary>
public sealed record NavItem(string Key, string Glyph, string LabelKey, string GroupKey = "");

public static class PageKeys
{
    public const string Dashboard = "Dashboard";
    public const string DnsManager = "DnsManager";
    public const string Resolvers = "Resolvers";
    public const string Routing = "Routing";
    public const string Gaming = "Gaming";
    public const string Bypass = "Bypass";
    public const string Filtering = "Filtering";
    public const string Diagnostics = "Diagnostics";
    public const string Monitor = "Monitor";
    public const string Connections = "Connections";
    public const string Settings = "Settings";
    public const string Appearance = "Appearance";
}

public interface IPageFactory
{
    PageViewModel Create(string pageKey);
}

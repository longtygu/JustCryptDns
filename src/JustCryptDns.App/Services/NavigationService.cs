namespace JustCryptDns.App.Services;

/// <summary>Decoupled navigation requests from pages to the shell.</summary>
public interface INavigationService
{
    event EventHandler<string>? NavigationRequested;

    void Navigate(string pageKey);

    string? ConsumePendingPageKey() => null;
}

public sealed class NavigationService : INavigationService
{
    private string? _pendingPageKey;

    public event EventHandler<string>? NavigationRequested;

    public void Navigate(string pageKey)
    {
        if (NavigationRequested is { } handler)
        {
            _pendingPageKey = null;
            handler(this, pageKey);
            return;
        }

        _pendingPageKey = pageKey;
    }

    public string? ConsumePendingPageKey()
    {
        var pending = _pendingPageKey;
        _pendingPageKey = null;
        return pending;
    }
}

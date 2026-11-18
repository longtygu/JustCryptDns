namespace JustCryptDns.App.Services;

/// <summary>Decoupled navigation requests from pages to the shell.</summary>
public interface INavigationService
{
    event EventHandler<string>? NavigationRequested;

    void Navigate(string pageKey);
}

public sealed class NavigationService : INavigationService
{
    public event EventHandler<string>? NavigationRequested;

    public void Navigate(string pageKey) => NavigationRequested?.Invoke(this, pageKey);
}

using System.Windows;
using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

public enum AboutWindowTab
{
    Overview = 0,
    HowItWorks = 1,
    BugReport = 2,
}

public interface IAboutWindowService
{
    void Show(AboutWindowTab initialTab = AboutWindowTab.Overview);
}

public sealed class AboutWindowService : IAboutWindowService
{
    private readonly IServiceProvider _services;
    private readonly IAppearanceService _appearance;
    private readonly IProcessPerformanceService _performance;
    private readonly ILogger<AboutWindowService> _logger;
    private AboutWindow? _activeWindow;
    private AboutViewModel? _activeViewModel;

    public AboutWindowService(
        IServiceProvider services,
        IAppearanceService appearance,
        IProcessPerformanceService performance,
        ILogger<AboutWindowService> logger)
    {
        _services = services;
        _appearance = appearance;
        _performance = performance;
        _logger = logger;
    }

    public void Show(AboutWindowTab initialTab = AboutWindowTab.Overview)
    {
        var app = Application.Current;
        if (app is null)
        {
            return;
        }

        if (!app.Dispatcher.CheckAccess())
        {
            app.Dispatcher.BeginInvoke(() => Show(initialTab));
            return;
        }

        if (_activeWindow is { } existing && _activeViewModel is { } existingVm)
        {
            existingVm.SelectTab(initialTab);
            if (existing.WindowState == WindowState.Minimized)
            {
                existing.WindowState = WindowState.Normal;
            }

            existing.Activate();
            existing.Focus();
            return;
        }

        var vm = _services.GetRequiredService<AboutViewModel>();
        vm.SelectTab(initialTab);

        var window = new AboutWindow(vm, _appearance);
        if (app.MainWindow is { IsVisible: true } owner)
        {
            window.Owner = owner;
        }

        window.Closed += (_, _) =>
        {
            _activeWindow = null;
            _activeViewModel?.Dispose();
            _activeViewModel = null;
            _ = Task.Run(() => _performance.TrimWorkingSet());
        };

        _activeWindow = window;
        _activeViewModel = vm;
        window.Show();
        window.Activate();
        _logger.LogDebug("Opened AboutWindow at tab {Tab}.", initialTab);
    }
}

using System.Windows;
using System.Windows.Controls;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.Views;

public partial class SettingsView : UserControl
{
    private SettingsViewModel? _boundVm;

    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        AttachVm(DataContext as SettingsViewModel);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        AttachVm(null);
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        AttachVm(e.NewValue as SettingsViewModel);
    }

    private void AttachVm(SettingsViewModel? vm)
    {
        if (ReferenceEquals(_boundVm, vm))
        {
            return;
        }

        if (_boundVm is not null)
        {
            _boundVm.DownloadProgressReceived -= OnDownloadProgressReceived;
            _boundVm.DownloadChartResetRequested -= OnDownloadChartResetRequested;
        }

        _boundVm = vm;
        if (_boundVm is not null)
        {
            _boundVm.DownloadProgressReceived += OnDownloadProgressReceived;
            _boundVm.DownloadChartResetRequested += OnDownloadChartResetRequested;
        }
    }

    private void OnDownloadProgressReceived(object? sender, UpdateDownloadProgress progress) =>
        UpdateSpeedChart.PushSample(progress);

    private void OnDownloadChartResetRequested(object? sender, EventArgs e) =>
        UpdateSpeedChart.Reset();
}

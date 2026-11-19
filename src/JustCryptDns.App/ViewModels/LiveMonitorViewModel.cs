using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed partial class LiveMonitorViewModel : PageViewModel
{
    private readonly INetworkDiagnosticsService _diagnostics;
    private readonly IDnsFailoverService _failover;
    private readonly IDnsEngine _dnsEngine;

    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private DnsEngineState _engineState = DnsEngineState.Stopped;
    [ObservableProperty] private string _activeResolverName = "—";
    [ObservableProperty] private long _totalQueries;
    [ObservableProperty] private long _blockedQueries;
    [ObservableProperty] private string _cacheHitRatioText = "0%";
    [ObservableProperty] private string _lastLatencyText = "—";

    public LiveMonitorViewModel(
        INetworkDiagnosticsService diagnostics,
        IDnsFailoverService failover,
        IDnsEngine dnsEngine)
        : base("Nav_Monitor", "Page_Monitor_Subtitle")
    {
        _diagnostics = diagnostics;
        _failover = failover;
        _dnsEngine = dnsEngine;

        _isPaused = _diagnostics.IsMonitorPaused;
        RefreshAll();
    }

    public ObservableCollection<LiveQueryMonitorEntry> QueryEntries { get; } = [];

    public ObservableCollection<FailoverEventEntry> FailoverEvents { get; } = [];

    public override void OnNavigatedTo()
    {
        _diagnostics.QueryObserved += OnQueryObserved;
        _failover.FailoverOccurred += OnFailoverOccurred;
        _dnsEngine.StateChanged += OnEngineStateChanged;
        RefreshAll();
    }

    public override void OnNavigatedFrom()
    {
        _diagnostics.QueryObserved -= OnQueryObserved;
        _failover.FailoverOccurred -= OnFailoverOccurred;
        _dnsEngine.StateChanged -= OnEngineStateChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _diagnostics.QueryObserved -= OnQueryObserved;
            _failover.FailoverOccurred -= OnFailoverOccurred;
            _dnsEngine.StateChanged -= OnEngineStateChanged;
        }

        base.Dispose(disposing);
    }

    partial void OnIsPausedChanged(bool value) => _diagnostics.IsMonitorPaused = value;

    [RelayCommand]
    private void ClearMonitor()
    {
        _diagnostics.ClearMonitorEntries();
        QueryEntries.Clear();
    }

    [RelayCommand]
    private void ClearFailoverHistory()
    {
        _failover.ClearHistory();
        FailoverEvents.Clear();
    }

    public void RefreshAll()
    {
        ApplyEngineStats(_dnsEngine.GetStats());

        QueryEntries.Clear();
        foreach (var entry in _diagnostics.GetMonitorEntries())
        {
            QueryEntries.Add(entry);
        }

        FailoverEvents.Clear();
        foreach (var ev in _failover.GetFailoverHistory())
        {
            FailoverEvents.Add(ev);
        }
    }

    private void ApplyEngineStats(DnsEngineRuntimeStats stats)
    {
        EngineState = stats.State;
        ActiveResolverName = stats.ActiveResolverName;
        TotalQueries = stats.TotalQueries;
        BlockedQueries = stats.BlockedQueries;
        CacheHitRatioText = string.Create(CultureInfo.InvariantCulture, $"{stats.CacheHitRatioPercent:0.#}%");
        LastLatencyText = stats.LastLatencyMs is { } ms
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms")
            : "—";
    }

    private void OnQueryObserved(object? sender, LiveQueryMonitorEntry entry)
    {
        void Add()
        {
            QueryEntries.Insert(0, entry);
            while (QueryEntries.Count > 300)
            {
                QueryEntries.RemoveAt(QueryEntries.Count - 1);
            }
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Add);
        }
        else
        {
            Add();
        }
    }

    private void OnFailoverOccurred(object? sender, FailoverEventEntry ev)
    {
        void Add()
        {
            FailoverEvents.Insert(0, ev);
            while (FailoverEvents.Count > 100)
            {
                FailoverEvents.RemoveAt(FailoverEvents.Count - 1);
            }
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Add);
        }
        else
        {
            Add();
        }
    }

    private void OnEngineStateChanged(object? sender, DnsEngineRuntimeStats stats)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyEngineStats(stats));
        }
        else
        {
            ApplyEngineStats(stats);
        }
    }
}

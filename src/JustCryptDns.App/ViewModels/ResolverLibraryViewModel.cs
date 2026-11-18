using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed partial class ResolverItemViewModel : ObservableObject
{
    [ObservableProperty] private DnsResolverEndpoint _resolver;
    [ObservableProperty] private bool _isPrimary;
    [ObservableProperty] private bool _isSecondary;
    [ObservableProperty] private bool? _isAvailable;
    [ObservableProperty] private string _latencyText = "—";
    [ObservableProperty] private string _reliabilityText = "—";
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private bool _isProbing;

    public ResolverItemViewModel(
        DnsResolverEndpoint resolver,
        bool isPrimary,
        bool isSecondary,
        ResolverHealthStatus health)
    {
        _resolver = resolver;
        _isPrimary = isPrimary;
        _isSecondary = isSecondary;
        ApplyHealth(health);
    }

    public string Id => Resolver.Id;

    public string Name => Resolver.Name;

    public string Provider => Resolver.Provider;

    public DnsProtocol Protocol => Resolver.Protocol;

    public string ProtocolBadge => Resolver.Protocol switch
    {
        DnsProtocol.DnsOverHttps => "DoH",
        DnsProtocol.DnsOverTls => "DoT",
        DnsProtocol.DnsCrypt => "DNSCrypt",
        DnsProtocol.UdpTcp => "UDP/TCP",
        _ => Resolver.Protocol.ToString(),
    };

    public string Endpoint => Resolver.Endpoint;

    public string Ipv4Display => string.IsNullOrWhiteSpace(Resolver.SecondaryIp)
        ? $"{Resolver.PrimaryIp}:{Resolver.Port}"
        : $"{Resolver.PrimaryIp} / {Resolver.SecondaryIp} (:{Resolver.Port})";

    public string Ipv6Display => string.IsNullOrWhiteSpace(Resolver.PrimaryIpv6)
        ? "—"
        : Resolver.PrimaryIpv6;

    public bool IsEncrypted => Resolver.IsEncrypted;

    public string FilteringKey => $"FilteringCap_{Resolver.Filtering}";

    public bool SupportsDnssec => Resolver.SupportsDnssec;

    public bool NoLogPolicy => Resolver.NoLogPolicy;

    public bool SupportsEcs => Resolver.SupportsEcs;

    public string GroupName => Resolver.GroupName;

    public bool IsCustom => Resolver.IsCustom;

    public bool IsEnabled => Resolver.IsEnabled;

    public string AvailabilityKey => IsAvailable switch
    {
        true => "Resolvers_Status_Online",
        false => "Resolvers_Status_Unreachable",
        null => "Resolvers_Status_Untested",
    };

    public void ApplyHealth(ResolverHealthStatus health)
    {
        IsAvailable = health.IsAvailable;
        LatencyText = health.LastLatencyMs is { } ms
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms")
            : "—";
        ReliabilityText = health.ReliabilityScore is { } score
            ? string.Create(CultureInfo.InvariantCulture, $"{score:0.#}%")
            : "—";
        LastError = health.LastError;
        OnPropertyChanged(nameof(AvailabilityKey));
    }
}

public sealed partial class ResolverLibraryViewModel : PageViewModel
{
    public const string AllFilterValue = "All";

    private readonly IResolverLibraryService _library;
    private readonly IDnsEngine _dnsEngine;

    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private string _selectedGroupFilter = AllFilterValue;
    [ObservableProperty] private string _selectedProtocolFilter = AllFilterValue;
    [ObservableProperty] private DnsResolverEndpoint _primaryResolver;
    [ObservableProperty] private DnsResolverEndpoint _secondaryResolver;
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private int _enabledCount;
    [ObservableProperty] private int _encryptedCount;
    [ObservableProperty] private int _customCount;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string _newGroupName = string.Empty;

    // Editor state
    [ObservableProperty] private bool _isEditorOpen;
    [ObservableProperty] private bool _isEditingExisting;
    [ObservableProperty] private string? _editingResolverId;
    [ObservableProperty] private string _editorName = string.Empty;
    [ObservableProperty] private string _editorProvider = "Custom";
    [ObservableProperty] private DnsProtocol _editorProtocol = DnsProtocol.DnsOverHttps;
    [ObservableProperty] private string _editorEndpoint = "https://";
    [ObservableProperty] private string _editorPrimaryIp = string.Empty;
    [ObservableProperty] private string _editorSecondaryIp = string.Empty;
    [ObservableProperty] private string _editorPrimaryIpv6 = string.Empty;
    [ObservableProperty] private string _editorPortText = "443";
    [ObservableProperty] private string _editorGroupName = ResolverGroups.General;
    [ObservableProperty] private DnsFilteringCapability _editorFiltering = DnsFilteringCapability.None;
    [ObservableProperty] private bool _editorSupportsDnssec = true;
    [ObservableProperty] private bool _editorNoLogPolicy = true;
    [ObservableProperty] private string? _editorErrorMessage;

    public ResolverLibraryViewModel(
        IResolverLibraryService library,
        IDnsEngine dnsEngine)
        : base("Nav_Resolvers", "Page_Resolvers_Subtitle")
    {
        _library = library;
        _dnsEngine = dnsEngine;

        _primaryResolver = _library.GetPrimaryResolver();
        _secondaryResolver = _library.GetSecondaryResolver();

        RefreshCatalog();
    }

    public ObservableCollection<ResolverItemViewModel> FilteredResolvers { get; } = [];

    public ObservableCollection<string> GroupFilterOptions { get; } = [];

    public ObservableCollection<string> AvailableGroups { get; } = [];

    public IReadOnlyList<string> ProtocolFilterOptions { get; } =
    [
        AllFilterValue,
        "DoH",
        "DoT",
        "DNSCrypt",
        "UDP/TCP",
    ];

    public IReadOnlyList<DnsProtocol> Protocols { get; } = Enum.GetValues<DnsProtocol>();

    public IReadOnlyList<DnsFilteringCapability> FilteringCapabilities { get; } = Enum.GetValues<DnsFilteringCapability>();

    public override void OnNavigatedTo()
    {
        _library.LibraryChanged += OnLibraryChanged;
        _library.HealthUpdated += OnHealthUpdated;
        RefreshCatalog();
    }

    public override void OnNavigatedFrom()
    {
        _library.LibraryChanged -= OnLibraryChanged;
        _library.HealthUpdated -= OnHealthUpdated;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _library.LibraryChanged -= OnLibraryChanged;
            _library.HealthUpdated -= OnHealthUpdated;
        }

        base.Dispose(disposing);
    }

    partial void OnSearchQueryChanged(string value) => ApplyFilters();

    partial void OnSelectedGroupFilterChanged(string value) => ApplyFilters();

    partial void OnSelectedProtocolFilterChanged(string value) => ApplyFilters();

    partial void OnEditorProtocolChanged(DnsProtocol value)
    {
        if (!IsEditingExisting)
        {
            EditorPortText = value switch
            {
                DnsProtocol.DnsOverTls => "853",
                DnsProtocol.UdpTcp => "53",
                _ => "443",
            };

            if (value == DnsProtocol.DnsOverHttps && string.IsNullOrWhiteSpace(EditorEndpoint))
            {
                EditorEndpoint = "https://";
            }
            else if (value == DnsProtocol.DnsCrypt && (string.IsNullOrWhiteSpace(EditorEndpoint) || EditorEndpoint == "https://"))
            {
                EditorEndpoint = "sdns://";
            }
            else if (value is DnsProtocol.DnsOverTls or DnsProtocol.UdpTcp && (EditorEndpoint == "https://" || EditorEndpoint == "sdns://"))
            {
                EditorEndpoint = string.Empty;
            }
        }
    }

    [RelayCommand]
    private void OpenAddResolver()
    {
        IsEditingExisting = false;
        EditingResolverId = null;
        EditorName = string.Empty;
        EditorProvider = "Custom";
        EditorProtocol = DnsProtocol.DnsOverHttps;
        EditorEndpoint = "https://";
        EditorPrimaryIp = string.Empty;
        EditorSecondaryIp = string.Empty;
        EditorPrimaryIpv6 = string.Empty;
        EditorPortText = "443";
        EditorGroupName = ResolverGroups.General;
        EditorFiltering = DnsFilteringCapability.None;
        EditorSupportsDnssec = true;
        EditorNoLogPolicy = true;
        EditorErrorMessage = null;
        IsEditorOpen = true;
    }

    [RelayCommand]
    private void OpenEditResolver(ResolverItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        var r = item.Resolver;
        IsEditingExisting = true;
        EditingResolverId = r.Id;
        EditorName = r.Name;
        EditorProvider = r.Provider;
        EditorProtocol = r.Protocol;
        EditorEndpoint = r.Endpoint;
        EditorPrimaryIp = r.PrimaryIp;
        EditorSecondaryIp = r.SecondaryIp ?? string.Empty;
        EditorPrimaryIpv6 = r.PrimaryIpv6 ?? string.Empty;
        EditorPortText = r.Port.ToString(CultureInfo.InvariantCulture);
        EditorGroupName = r.GroupName;
        EditorFiltering = r.Filtering;
        EditorSupportsDnssec = r.SupportsDnssec;
        EditorNoLogPolicy = r.NoLogPolicy;
        EditorErrorMessage = null;
        IsEditorOpen = true;
    }

    [RelayCommand]
    private void CancelEditor()
    {
        IsEditorOpen = false;
        EditorErrorMessage = null;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SaveEditorAsync()
    {
        if (!int.TryParse(EditorPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
        {
            EditorErrorMessage = LocalizationManager.Instance["Resolvers_Err_InvalidPort"];
            return;
        }

        var candidate = new DnsResolverEndpoint
        {
            Id = EditingResolverId ?? string.Empty,
            Name = EditorName.Trim(),
            Provider = EditorProvider.Trim(),
            Protocol = EditorProtocol,
            Endpoint = EditorEndpoint.Trim(),
            PrimaryIp = EditorPrimaryIp.Trim(),
            SecondaryIp = string.IsNullOrWhiteSpace(EditorSecondaryIp) ? null : EditorSecondaryIp.Trim(),
            PrimaryIpv6 = string.IsNullOrWhiteSpace(EditorPrimaryIpv6) ? null : EditorPrimaryIpv6.Trim(),
            Port = port,
            GroupName = string.IsNullOrWhiteSpace(EditorGroupName) ? ResolverGroups.General : EditorGroupName.Trim(),
            Filtering = EditorFiltering,
            SupportsDnssec = EditorSupportsDnssec,
            NoLogPolicy = EditorNoLogPolicy,
            IsCustom = true,
            IsEnabled = true,
        };

        (bool Success, DnsResolverEndpoint? Resolver, ResolverValidationResult Validation) result;
        if (IsEditingExisting && !string.IsNullOrWhiteSpace(EditingResolverId))
        {
            result = await _library.UpdateResolverAsync(candidate);
        }
        else
        {
            result = await _library.AddCustomResolverAsync(candidate);
        }

        if (!result.Success)
        {
            EditorErrorMessage = result.Validation.ErrorKey is { } key
                ? LocalizationManager.Instance[key]
                : result.Validation.ErrorMessage;
            return;
        }

        IsEditorOpen = false;
        EditorErrorMessage = null;
        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_Saved", result.Resolver!.Name);
        RefreshCatalog();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveResolverAsync(ResolverItemViewModel? item)
    {
        if (item is null || !item.IsCustom)
        {
            return;
        }

        var removed = await _library.RemoveCustomResolverAsync(item.Id);
        if (removed)
        {
            ErrorMessage = null;
            StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_Removed", item.Name);
            RefreshCatalog();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleEnabledAsync(ResolverItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        await _library.SetResolverEnabledAsync(item.Id, !item.IsEnabled);
        RefreshCatalog();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SetPrimaryAsync(ResolverItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        var (ok, err) = await _library.SetPrimaryResolverAsync(item.Id);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        var (switchOk, switchErr) = await _dnsEngine.SwitchResolverAsync(item.Id);
        if (!switchOk)
        {
            ErrorMessage = switchErr;
            return;
        }

        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_PrimarySet", item.Name);
        RefreshCatalog();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SetSecondaryAsync(ResolverItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        var (ok, err) = await _library.SetSecondaryResolverAsync(item.Id);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_SecondarySet", item.Name);
        RefreshCatalog();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CheckSingleHealthAsync(ResolverItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        item.IsProbing = true;
        try
        {
            var status = await _library.CheckHealthAsync(item.Id);
            item.ApplyHealth(status);
            if (status.IsAvailable == true && status.LastLatencyMs is { } ms)
            {
                ErrorMessage = null;
                StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_ProbeOk", item.Name, Math.Round(ms, 1));
            }
            else
            {
                ErrorMessage = $"{item.Name}: {status.LastError ?? LocalizationManager.Instance["Resolvers_Status_Unreachable"]}";
            }
        }
        finally
        {
            item.IsProbing = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CheckAllHealthAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance["Resolvers_Msg_ProbingAll"];
        try
        {
            var results = await _library.CheckAllEnabledHealthAsync();
            var online = results.Count(r => r.IsAvailable == true);
            StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_ProbeAllDone", online, results.Count);
            RefreshCatalog();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddGroupAsync()
    {
        if (string.IsNullOrWhiteSpace(NewGroupName))
        {
            return;
        }

        var name = NewGroupName.Trim();
        await _library.AddGroupAsync(name);
        NewGroupName = string.Empty;
        RefreshCatalog();
        SelectedGroupFilter = name;
    }

    [RelayCommand]
    private void ExportProfile()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "JustCryptDns Resolver Profile (*.json)|*.json",
            FileName = "justcryptdns-resolvers.json",
            DefaultExt = ".json",
        };

        if (dialog.ShowDialog() == true)
        {
            var json = _library.ExportProfileJson();
            File.WriteAllText(dialog.FileName, json);
            ErrorMessage = null;
            StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_Exported", Path.GetFileName(dialog.FileName));
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ImportProfileAsync()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "JustCryptDns Resolver Profile (*.json)|*.json",
            DefaultExt = ".json",
        };

        if (dialog.ShowDialog() == true)
        {
            var json = await File.ReadAllTextAsync(dialog.FileName);
            var (ok, count, err) = await _library.ImportProfileJsonAsync(json);
            if (ok)
            {
                ErrorMessage = null;
                StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_Imported", count);
                RefreshCatalog();
            }
            else
            {
                ErrorMessage = err;
            }
        }
    }

    public void RefreshCatalog()
    {
        var all = _library.GetAll();
        PrimaryResolver = _library.GetPrimaryResolver();
        SecondaryResolver = _library.GetSecondaryResolver();

        TotalCount = all.Count;
        EnabledCount = all.Count(r => r.IsEnabled);
        EncryptedCount = all.Count(r => r.IsEncrypted);
        CustomCount = all.Count(r => r.IsCustom);

        var groups = _library.GetGroups();
        var prevGroup = SelectedGroupFilter;
        GroupFilterOptions.Clear();
        GroupFilterOptions.Add(AllFilterValue);
        AvailableGroups.Clear();
        foreach (var g in groups)
        {
            GroupFilterOptions.Add(g);
            AvailableGroups.Add(g);
        }

        if (!GroupFilterOptions.Contains(prevGroup))
        {
            SelectedGroupFilter = AllFilterValue;
        }

        ApplyFilters();
    }

    private void ApplyFilters()
    {
        var all = _library.GetAll();
        var primaryId = PrimaryResolver.Id;
        var secondaryId = SecondaryResolver.Id;
        var query = SearchQuery?.Trim() ?? string.Empty;

        FilteredResolvers.Clear();
        foreach (var r in all)
        {
            if (!string.Equals(SelectedGroupFilter, AllFilterValue, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(r.GroupName, SelectedGroupFilter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!MatchesProtocolFilter(r.Protocol, SelectedProtocolFilter))
            {
                continue;
            }

            if (!string.IsNullOrEmpty(query)
                && !r.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
                && !r.Provider.Contains(query, StringComparison.OrdinalIgnoreCase)
                && !r.Endpoint.Contains(query, StringComparison.OrdinalIgnoreCase)
                && !r.PrimaryIp.Contains(query, StringComparison.OrdinalIgnoreCase)
                && !(r.PrimaryIpv6?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
            {
                continue;
            }

            var isPrimary = string.Equals(r.Id, primaryId, StringComparison.OrdinalIgnoreCase);
            var isSecondary = string.Equals(r.Id, secondaryId, StringComparison.OrdinalIgnoreCase);
            var health = _library.GetHealth(r.Id);
            FilteredResolvers.Add(new ResolverItemViewModel(r, isPrimary, isSecondary, health));
        }
    }

    private static bool MatchesProtocolFilter(DnsProtocol protocol, string filter)
    {
        if (string.IsNullOrWhiteSpace(filter) || string.Equals(filter, AllFilterValue, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return filter switch
        {
            "DoH" => protocol == DnsProtocol.DnsOverHttps,
            "DoT" => protocol == DnsProtocol.DnsOverTls,
            "DNSCrypt" => protocol == DnsProtocol.DnsCrypt,
            "UDP/TCP" => protocol == DnsProtocol.UdpTcp,
            _ => true,
        };
    }

    private void OnLibraryChanged(object? sender, EventArgs e)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(RefreshCatalog);
        }
        else
        {
            RefreshCatalog();
        }
    }

    private void OnHealthUpdated(object? sender, ResolverHealthStatus health)
    {
        void Apply()
        {
            var match = FilteredResolvers.FirstOrDefault(x => string.Equals(x.Id, health.ResolverId, StringComparison.OrdinalIgnoreCase));
            match?.ApplyHealth(health);
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Apply);
        }
        else
        {
            Apply();
        }
    }
}

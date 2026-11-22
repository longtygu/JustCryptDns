using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed class RoutingRuleItemViewModel
{
    public RoutingRuleItemViewModel(DnsRoutingRule rule, DnsResolverEndpoint resolver)
    {
        Rule = rule;
        Resolver = resolver;
    }

    public DnsRoutingRule Rule { get; }

    public DnsResolverEndpoint Resolver { get; }

    public string Id => Rule.Id;

    public string Name => Rule.Name;

    public string Pattern => Rule.Pattern;

    public RoutingMatchKind MatchKind => Rule.MatchKind;

    public string MatchKindKey => $"RoutingMatch_{Rule.MatchKind}";

    public int Priority => Rule.Priority;

    public bool IsEnabled => Rule.IsEnabled;

    public string ResolverName => Resolver.Name;

    public string ProtocolBadge => Resolver.Protocol switch
    {
        DnsProtocol.DnsOverHttps => "DoH",
        DnsProtocol.DnsOverTls => "DoT",
        DnsProtocol.DnsCrypt => "DNSCrypt",
        DnsProtocol.UdpTcp => "UDP/TCP",
        _ => Resolver.Protocol.ToString(),
    };
}

public sealed partial class RoutingViewModel : PageViewModel
{
    private readonly IDnsRoutingService _routing;
    private readonly IResolverLibraryService _resolvers;
    private bool _loading;

    [ObservableProperty] private bool _isRoutingEnabled = true;
    [ObservableProperty] private DnsRoutingProfile _selectedProfile;
    [ObservableProperty] private DnsResolverEndpoint _selectedFallbackResolver;
    [ObservableProperty] private string _newProfileName = string.Empty;
    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;

    // Rule editor state
    [ObservableProperty] private bool _isRuleEditorOpen;
    [ObservableProperty] private string? _editingRuleId;
    [ObservableProperty] private string _ruleName = string.Empty;
    [ObservableProperty] private string _rulePattern = string.Empty;
    [ObservableProperty] private RoutingMatchKind _ruleMatchKind = RoutingMatchKind.DomainSuffix;
    [ObservableProperty] private DnsResolverEndpoint _ruleResolver;
    [ObservableProperty] private string _rulePriorityText = "50";
    [ObservableProperty] private string? _ruleEditorError;

    // Rule tester state
    [ObservableProperty] private string _testDomainInput = "store.steampowered.com";
    [ObservableProperty] private RoutingDecision? _lastTestDecision;
    [ObservableProperty] private string? _lastTestSummary;

    // Local DNS rewrite state
    [ObservableProperty] private string _rewriteDomain = string.Empty;
    [ObservableProperty] private LocalDnsRewriteRecordType _rewriteRecordType = LocalDnsRewriteRecordType.A;
    [ObservableProperty] private string _rewriteTarget = string.Empty;
    [ObservableProperty] private string _rewriteTtlText = "60";
    [ObservableProperty] private string? _rewriteError;

    public RoutingViewModel(
        IDnsRoutingService routing,
        IResolverLibraryService resolvers)
        : base("Nav_Routing", "Page_Routing_Subtitle")
    {
        _routing = routing;
        _resolvers = resolvers;

        _loading = true;
        _isRoutingEnabled = _routing.IsRoutingEnabled;
        _selectedProfile = _routing.GetActiveProfile();
        _selectedFallbackResolver = _resolvers.GetByIdOrDefault(_selectedProfile.FallbackResolverId);
        _ruleResolver = _selectedFallbackResolver;
        _loading = false;

        RefreshAll();
    }

    public ObservableCollection<DnsRoutingProfile> Profiles { get; } = [];

    public ObservableCollection<RoutingRuleItemViewModel> ProfileRules { get; } = [];

    public ObservableCollection<LocalDnsRewriteRule> LocalRewrites { get; } = [];

    public ObservableCollection<RoutingLogEntry> RecentLogs { get; } = [];

    public IReadOnlyList<DnsResolverEndpoint> AvailableResolvers => _resolvers.GetEnabled();

    public IReadOnlyList<RoutingMatchKind> MatchKinds { get; } = Enum.GetValues<RoutingMatchKind>();

    public IReadOnlyList<LocalDnsRewriteRecordType> RewriteRecordTypes { get; } = Enum.GetValues<LocalDnsRewriteRecordType>();

    public bool HasNoLocalRewrites => LocalRewrites.Count == 0;

    public bool CanDeleteSelectedProfile => SelectedProfile is { IsBuiltIn: false };

    public override void OnNavigatedTo()
    {
        _routing.RoutingChanged += OnRoutingChanged;
        _routing.LogAdded += OnLogAdded;
        _resolvers.LibraryChanged += OnRoutingChanged;
        RefreshAll();
    }

    public override void OnNavigatedFrom()
    {
        _routing.RoutingChanged -= OnRoutingChanged;
        _routing.LogAdded -= OnLogAdded;
        _resolvers.LibraryChanged -= OnRoutingChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _routing.RoutingChanged -= OnRoutingChanged;
            _routing.LogAdded -= OnLogAdded;
            _resolvers.LibraryChanged -= OnRoutingChanged;
        }

        base.Dispose(disposing);
    }

    partial void OnIsRoutingEnabledChanged(bool value)
    {
        if (!_loading)
        {
            _ = _routing.SetRoutingEnabledAsync(value);
        }
    }

    partial void OnSelectedProfileChanged(DnsRoutingProfile value)
    {
        OnPropertyChanged(nameof(CanDeleteSelectedProfile));
        if (_loading || value is null)
        {
            return;
        }

        _ = SwitchProfileInternalAsync(value.Id);
    }

    partial void OnSelectedFallbackResolverChanged(DnsResolverEndpoint value)
    {
        if (_loading || value is null || SelectedProfile is null)
        {
            return;
        }

        _ = _routing.SetProfileFallbackResolverAsync(SelectedProfile.Id, value.Id);
    }

    [RelayCommand]
    private void OpenAddRule()
    {
        EditingRuleId = null;
        RuleName = string.Empty;
        RulePattern = string.Empty;
        RuleMatchKind = RoutingMatchKind.DomainSuffix;
        RuleResolver = SelectedFallbackResolver ?? _resolvers.GetPrimaryResolver();
        RulePriorityText = "50";
        RuleEditorError = null;
        IsRuleEditorOpen = true;
    }

    [RelayCommand]
    private void OpenEditRule(RoutingRuleItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        EditingRuleId = item.Rule.Id;
        RuleName = item.Rule.Name;
        RulePattern = item.Rule.Pattern;
        RuleMatchKind = item.Rule.MatchKind;
        RuleResolver = item.Resolver;
        RulePriorityText = item.Rule.Priority.ToString(CultureInfo.InvariantCulture);
        RuleEditorError = null;
        IsRuleEditorOpen = true;
    }

    [RelayCommand]
    private void CancelRuleEditor()
    {
        IsRuleEditorOpen = false;
        RuleEditorError = null;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SaveRuleAsync()
    {
        if (!int.TryParse(RulePriorityText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var priority) || priority is < 1 or > 9999)
        {
            RuleEditorError = LocalizationManager.Instance["Routing_Err_InvalidPriority"];
            return;
        }

        var candidate = new DnsRoutingRule
        {
            Id = EditingRuleId ?? string.Empty,
            ProfileId = SelectedProfile.Id,
            Name = RuleName.Trim(),
            Pattern = RulePattern.Trim(),
            MatchKind = RuleMatchKind,
            ResolverId = (RuleResolver ?? _resolvers.GetPrimaryResolver()).Id,
            Priority = priority,
            IsEnabled = true,
        };

        var (ok, saved, err) = await _routing.AddOrUpdateRuleAsync(candidate);
        if (!ok)
        {
            RuleEditorError = err;
            return;
        }

        IsRuleEditorOpen = false;
        RuleEditorError = null;
        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance.Format("Routing_Msg_RuleSaved", saved!.Name);
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveRuleAsync(RoutingRuleItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        if (await _routing.RemoveRuleAsync(item.Id))
        {
            ErrorMessage = null;
            StatusMessage = LocalizationManager.Instance.Format("Routing_Msg_RuleRemoved", item.Name);
            RefreshAll();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleRuleEnabledAsync(RoutingRuleItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        await _routing.SetRuleEnabledAsync(item.Id, !item.IsEnabled);
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddProfileAsync()
    {
        if (string.IsNullOrWhiteSpace(NewProfileName))
        {
            return;
        }

        var (ok, profile, err) = await _routing.AddCustomProfileAsync(
            NewProfileName.Trim(),
            string.Empty,
            SelectedFallbackResolver.Id);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        NewProfileName = string.Empty;
        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance.Format("Routing_Msg_ProfileCreated", profile!.Name);
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveSelectedProfileAsync()
    {
        if (SelectedProfile is null || SelectedProfile.IsBuiltIn)
        {
            return;
        }

        var name = SelectedProfile.Name;
        if (await _routing.RemoveCustomProfileAsync(SelectedProfile.Id))
        {
            ErrorMessage = null;
            StatusMessage = LocalizationManager.Instance.Format("Routing_Msg_ProfileRemoved", name);
            RefreshAll();
        }
    }

    [RelayCommand]
    private void TestDomain()
    {
        if (string.IsNullOrWhiteSpace(TestDomainInput))
        {
            return;
        }

        var decision = _routing.ResolveForDomain(TestDomainInput, SelectedProfile.Id);
        LastTestDecision = decision;
        LastTestSummary = decision.IsFallback
            ? LocalizationManager.Instance.Format("Routing_Test_FallbackResult", decision.Domain, decision.ResolverName, decision.Protocol)
            : LocalizationManager.Instance.Format("Routing_Test_MatchedResult", decision.Domain, decision.MatchedRuleName ?? "Rule", decision.MatchedPattern ?? "", decision.ResolverName, decision.Protocol);

        _routing.RecordRoutingLog(decision, "TEST", null);
        RefreshLogs();
    }

    [RelayCommand]
    private void ClearLogs()
    {
        _routing.ClearLogs();
        RefreshLogs();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddLocalRewriteAsync()
    {
        RewriteError = null;
        var rawPattern = RewriteDomain?.Trim() ?? string.Empty;
        var matchKind = rawPattern.Contains('*', StringComparison.Ordinal)
            ? RoutingMatchKind.Wildcard
            : RoutingMatchKind.Exact;
        var ttl = int.TryParse(RewriteTtlText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedTtl)
            ? parsedTtl
            : 60;

        var rule = new LocalDnsRewriteRule
        {
            Id = string.Empty,
            Pattern = rawPattern,
            MatchKind = matchKind,
            RecordType = RewriteRecordType,
            TargetValue = RewriteTarget?.Trim() ?? string.Empty,
            TtlSeconds = ttl,
            IsEnabled = true,
        };

        var (ok, _, error) = await _routing.AddOrUpdateLocalRewriteAsync(rule);
        if (!ok)
        {
            RewriteError = error ?? "Invalid local rewrite rule.";
            return;
        }

        RewriteDomain = string.Empty;
        RewriteTarget = string.Empty;
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleLocalRewriteAsync(LocalDnsRewriteRule? rule)
    {
        if (rule is null)
        {
            return;
        }

        await _routing.SetLocalRewriteEnabledAsync(rule.Id, !rule.IsEnabled);
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveLocalRewriteAsync(LocalDnsRewriteRule? rule)
    {
        if (rule is null)
        {
            return;
        }

        await _routing.RemoveLocalRewriteAsync(rule.Id);
        RefreshAll();
    }

    public void RefreshAll()
    {
        _loading = true;
        try
        {
            IsRoutingEnabled = _routing.IsRoutingEnabled;
            OnPropertyChanged(nameof(AvailableResolvers));

            var profiles = _routing.GetProfiles();
            var active = _routing.GetActiveProfile();

            Profiles.Clear();
            foreach (var p in profiles)
            {
                Profiles.Add(p);
            }

            SelectedProfile = Profiles.FirstOrDefault(p => string.Equals(p.Id, active.Id, StringComparison.OrdinalIgnoreCase)) ?? Profiles[0];
            SelectedFallbackResolver = _resolvers.GetByIdOrDefault(SelectedProfile.FallbackResolverId);

            ProfileRules.Clear();
            foreach (var rule in _routing.GetRulesForProfile(SelectedProfile.Id))
            {
                var resolver = _resolvers.GetByIdOrDefault(rule.ResolverId);
                ProfileRules.Add(new RoutingRuleItemViewModel(rule, resolver));
            }

            LocalRewrites.Clear();
            foreach (var rewrite in _routing.GetLocalRewrites())
            {
                LocalRewrites.Add(rewrite);
            }

            OnPropertyChanged(nameof(HasNoLocalRewrites));
            RefreshLogs();
        }
        finally
        {
            _loading = false;
        }
    }

    private void RefreshLogs()
    {
        RecentLogs.Clear();
        foreach (var entry in _routing.GetRecentLogs())
        {
            RecentLogs.Add(entry);
        }
    }

    private async Task SwitchProfileInternalAsync(string profileId)
    {
        await _routing.SetActiveProfileAsync(profileId);
        RefreshAll();
    }

    private void OnRoutingChanged(object? sender, EventArgs e)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(RefreshAll);
        }
        else
        {
            RefreshAll();
        }
    }

    private void OnLogAdded(object? sender, RoutingLogEntry entry)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(RefreshLogs);
        }
        else
        {
            RefreshLogs();
        }
    }
}

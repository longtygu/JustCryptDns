using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed partial class ConnectionRowViewModel : ObservableObject
{
    private readonly Action<ConnectionRowViewModel, string>? _noteCommitted;
    private string _note = string.Empty;

    public ConnectionRowViewModel(string key, Action<ConnectionRowViewModel, string>? noteCommitted = null)
    {
        Key = key;
        _noteCommitted = noteCommitted;
    }

    public string Key { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FirstSeenText))]
    private DateTimeOffset _firstSeen;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastSeenText))]
    private DateTimeOffset _lastSeen;

    [ObservableProperty]
    private int _processId;

    [ObservableProperty]
    private string _processName = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _executablePath;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProtocolLabel))]
    private ConnectionProtocol _protocol;

    [ObservableProperty]
    private string _remoteIp = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PortText))]
    private int _remotePort;

    [ObservableProperty]
    private int _connectionCount = 1;

    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private ConnectionDisplayStatus _status = ConnectionDisplayStatus.Active;

    [ObservableProperty]
    private string _organization = string.Empty;

    [ObservableProperty]
    private bool _isLan;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private ProcessTrustLevel _trustLevel = ProcessTrustLevel.Unknown;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _publisher;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _riskReason;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private bool _isThreatMatch;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _threatLabel;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    private bool _isAppBlocked;

    public string FirstSeenText => FirstSeen.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string LastSeenText => LastSeen.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string ProtocolLabel => Protocol switch
    {
        ConnectionProtocol.Tcp4 => "TCP",
        ConnectionProtocol.Tcp6 => "TCP6",
        ConnectionProtocol.Udp4 => "UDP",
        ConnectionProtocol.Udp6 => "UDP6",
        _ => "TCP",
    };

    public string PortText => Protocol is ConnectionProtocol.Udp4 or ConnectionProtocol.Udp6
        ? string.Create(CultureInfo.InvariantCulture, $"{RemotePort} (local)")
        : RemotePort.ToString(CultureInfo.InvariantCulture);

    public string StatusText => LocalizationManager.Instance.Get("ConnStatus_" + Status);

    public string TrustBadgeText
    {
        get
        {
            if (IsThreatMatch && !string.IsNullOrWhiteSpace(ThreatLabel))
            {
                return LocalizationManager.Instance.Format("Conn_Threat_MatchBadge", ThreatLabel);
            }

            if (IsAppBlocked)
            {
                return LocalizationManager.Instance.Get("Conn_AppBlocked_Badge");
            }

            var baseText = LocalizationManager.Instance.Get("Trust_" + TrustLevel);
            if ((TrustLevel is ProcessTrustLevel.Signed or ProcessTrustLevel.TrustedSystem)
                && !string.IsNullOrWhiteSpace(Publisher))
            {
                return $"{baseText} ({Publisher})";
            }

            return baseText;
        }
    }

    public string TrustTooltip
    {
        get
        {
            var sb = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(ExecutablePath))
            {
                sb.AppendLine(ExecutablePath);
            }

            if (!string.IsNullOrWhiteSpace(Publisher))
            {
                sb.AppendLine(Publisher);
            }

            if (!string.IsNullOrWhiteSpace(RiskReason))
            {
                sb.AppendLine(RiskReason);
            }

            if (IsThreatMatch && !string.IsNullOrWhiteSpace(ThreatLabel))
            {
                sb.Append(ThreatLabel);
            }

            return sb.ToString().Trim();
        }
    }

    public string Note
    {
        get => _note;
        set
        {
            var sanitized = value ?? string.Empty;
            if (SetProperty(ref _note, sanitized))
            {
                _noteCommitted?.Invoke(this, sanitized);
            }
        }
    }

    public void SetNoteSilent(string note)
    {
        var sanitized = note ?? string.Empty;
        if (!string.Equals(_note, sanitized, StringComparison.Ordinal))
        {
            _note = sanitized;
            OnPropertyChanged(nameof(Note));
        }
    }

    public void NotifyLocalizationChanged()
    {
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(TrustBadgeText));
    }
}

public sealed record BlockedRuleItemViewModel(string Target, string? Note, DateTimeOffset AddedAtUtc, bool IsEnabled);

public sealed record BlockedAppItemViewModel(string ExecutablePath, string ProcessName, string? Note, DateTimeOffset AddedAtUtc, bool IsEnabled);

public sealed record IpNoteItemViewModel(string Ip, string Note);

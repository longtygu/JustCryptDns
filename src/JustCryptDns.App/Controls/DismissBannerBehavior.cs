using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Attached behavior providing uniform one-click dismiss (<c>✕</c>) support for alert, warning,
/// error, and feedback banners across all views.
/// <list type="bullet">
///   <item>When <see cref="PersistKeyProperty"/> is set (polled/persistent warnings such as IPv6 leak or unencrypted DNS),
///   dismissing suppresses that exact warning signature for the current app session across polling ticks and page navigation,
///   while automatically showing again if a different warning text occurs.</item>
///   <item>When <see cref="PersistKeyProperty"/> is omitted (one-shot status/error banners),
///   dismissing clears the bound ViewModel property (if writable) and collapses the banner cleanly.</item>
/// </list>
/// </summary>
public static class DismissBannerBehavior
{
    private static readonly object Sync = new();
    private static readonly HashSet<string> DismissedSignatures = new(StringComparer.Ordinal);
    private static readonly List<WeakReference<FrameworkElement>> LivePersistentBanners = [];

    public static readonly DependencyProperty BannerContentProperty = DependencyProperty.RegisterAttached(
        "BannerContent",
        typeof(object),
        typeof(DismissBannerBehavior),
        new PropertyMetadata(null, OnBannerStateChanged));

    public static readonly DependencyProperty PersistKeyProperty = DependencyProperty.RegisterAttached(
        "PersistKey",
        typeof(string),
        typeof(DismissBannerBehavior),
        new PropertyMetadata(null, OnPersistKeyChanged));

    public static readonly DependencyProperty InvertBoolProperty = DependencyProperty.RegisterAttached(
        "InvertBool",
        typeof(bool),
        typeof(DismissBannerBehavior),
        new PropertyMetadata(false, OnBannerStateChanged));

    public static readonly DependencyProperty IsDismissButtonProperty = DependencyProperty.RegisterAttached(
        "IsDismissButton",
        typeof(bool),
        typeof(DismissBannerBehavior),
        new PropertyMetadata(false, OnIsDismissButtonChanged));

    private static readonly DependencyProperty IsLocallyDismissedProperty = DependencyProperty.RegisterAttached(
        "IsLocallyDismissed",
        typeof(bool),
        typeof(DismissBannerBehavior),
        new PropertyMetadata(false));

    public static object? GetBannerContent(DependencyObject obj) => obj.GetValue(BannerContentProperty);

    public static void SetBannerContent(DependencyObject obj, object? value) => obj.SetValue(BannerContentProperty, value);

    public static string? GetPersistKey(DependencyObject obj) => (string?)obj.GetValue(PersistKeyProperty);

    public static void SetPersistKey(DependencyObject obj, string? value) => obj.SetValue(PersistKeyProperty, value);

    public static bool GetInvertBool(DependencyObject obj) => (bool)obj.GetValue(InvertBoolProperty);

    public static void SetInvertBool(DependencyObject obj, bool value) => obj.SetValue(InvertBoolProperty, value);

    public static bool GetIsDismissButton(DependencyObject obj) => (bool)obj.GetValue(IsDismissButtonProperty);

    public static void SetIsDismissButton(DependencyObject obj, bool value) => obj.SetValue(IsDismissButtonProperty, value);

    /// <summary>Clears all session-dismissed signatures (useful in unit tests).</summary>
    public static void ResetSessionDismissals()
    {
        lock (Sync)
        {
            DismissedSignatures.Clear();
        }
    }

    public static bool IsSignatureDismissed(string persistKey, object? content)
    {
        var sig = BuildSignature(persistKey, content);
        lock (Sync)
        {
            return DismissedSignatures.Contains(sig);
        }
    }

    private static void OnPersistKeyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FrameworkElement element)
        {
            if (!string.IsNullOrWhiteSpace(e.NewValue as string))
            {
                RegisterLiveBanner(element);
            }

            UpdateBannerVisibility(element);
        }
    }

    private static void OnBannerStateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FrameworkElement element)
        {
            // A fresh value arriving resets any local dismissal for non-persistent banners.
            element.SetValue(IsLocallyDismissedProperty, false);
            UpdateBannerVisibility(element);
        }
    }

    private static void OnIsDismissButtonChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not Button button)
        {
            return;
        }

        button.Click -= OnDismissButtonClick;
        if (e.NewValue is true)
        {
            button.Click += OnDismissButtonClick;
        }
    }

    private static void OnDismissButtonClick(object sender, RoutedEventArgs e)
    {
        if (sender is not DependencyObject source)
        {
            return;
        }

        var banner = FindAncestorBanner(source);
        if (banner is null)
        {
            return;
        }

        DismissBanner(banner);
    }

    public static void DismissBanner(FrameworkElement banner)
    {
        ArgumentNullException.ThrowIfNull(banner);

        var persistKey = GetPersistKey(banner);
        var content = GetBannerContent(banner);

        if (!string.IsNullOrWhiteSpace(persistKey))
        {
            var sig = BuildSignature(persistKey, content);
            lock (Sync)
            {
                DismissedSignatures.Add(sig);
            }

            RefreshLiveBannersWithKey(persistKey);
        }
        else
        {
            banner.SetValue(IsLocallyDismissedProperty, true);
            TryClearBoundViewModelProperty(banner);
            UpdateBannerVisibility(banner);
        }
    }

    private static void UpdateBannerVisibility(FrameworkElement banner)
    {
        var content = GetBannerContent(banner);
        var invertBool = GetInvertBool(banner);

        if (!HasActiveContent(content, invertBool))
        {
            banner.Visibility = Visibility.Collapsed;
            return;
        }

        var persistKey = GetPersistKey(banner);
        if (!string.IsNullOrWhiteSpace(persistKey))
        {
            var sig = BuildSignature(persistKey, content);
            bool dismissed;
            lock (Sync)
            {
                dismissed = DismissedSignatures.Contains(sig);
            }

            banner.Visibility = dismissed ? Visibility.Collapsed : Visibility.Visible;
            return;
        }

        var locallyDismissed = (bool)banner.GetValue(IsLocallyDismissedProperty);
        banner.Visibility = locallyDismissed ? Visibility.Collapsed : Visibility.Visible;
    }

    private static bool HasActiveContent(object? content, bool invertBool) => content switch
    {
        null => false,
        bool b => invertBool ? !b : b,
        string s => !string.IsNullOrWhiteSpace(s),
        _ => true,
    };

    private static string BuildSignature(string persistKey, object? content)
    {
        var token = content switch
        {
            null => string.Empty,
            string s => s.Trim(),
            _ => content.ToString() ?? string.Empty,
        };
        return $"{persistKey}|{token}";
    }

    private static FrameworkElement? FindAncestorBanner(DependencyObject start)
    {
        var current = start;
        while (current is not null)
        {
            if (current is FrameworkElement fe
                && (fe.ReadLocalValue(BannerContentProperty) != DependencyProperty.UnsetValue
                    || !string.IsNullOrWhiteSpace(GetPersistKey(fe))))
            {
                return fe;
            }

            current = VisualTreeHelper.GetParent(current) ?? LogicalTreeHelper.GetParent(current);
        }

        return null;
    }

    private static void TryClearBoundViewModelProperty(FrameworkElement banner)
    {
        var binding = BindingOperations.GetBinding(banner, BannerContentProperty);
        var path = binding?.Path?.Path;
        var dataContext = banner.DataContext;
        if (dataContext is null || string.IsNullOrWhiteSpace(path) || path.Contains('.'))
        {
            return;
        }

        var prop = dataContext.GetType().GetProperty(path, BindingFlags.Instance | BindingFlags.Public);
        if (prop is null || !prop.CanWrite)
        {
            return;
        }

        try
        {
            if (prop.PropertyType == typeof(string) || !prop.PropertyType.IsValueType)
            {
                prop.SetValue(dataContext, null);
            }
            else if (prop.PropertyType == typeof(bool))
            {
                prop.SetValue(dataContext, GetInvertBool(banner));
            }
        }
        catch
        {
            // Banner is already locally collapsed; ignore non-writable or guarded properties.
        }
    }

    private static void RegisterLiveBanner(FrameworkElement banner)
    {
        lock (Sync)
        {
            PruneLiveBannersLocked();
            foreach (var weak in LivePersistentBanners)
            {
                if (weak.TryGetTarget(out var target) && ReferenceEquals(target, banner))
                {
                    return;
                }
            }

            LivePersistentBanners.Add(new WeakReference<FrameworkElement>(banner));
        }
    }

    private static void RefreshLiveBannersWithKey(string persistKey)
    {
        List<FrameworkElement> matching = [];
        lock (Sync)
        {
            PruneLiveBannersLocked();
            foreach (var weak in LivePersistentBanners)
            {
                if (weak.TryGetTarget(out var target))
                {
                    matching.Add(target);
                }
            }
        }

        foreach (var fe in matching)
        {
            void Update()
            {
                if (string.Equals(GetPersistKey(fe), persistKey, StringComparison.Ordinal))
                {
                    UpdateBannerVisibility(fe);
                }
            }

            if (fe.Dispatcher.CheckAccess())
            {
                Update();
            }
            else
            {
                fe.Dispatcher.BeginInvoke(Update);
            }
        }
    }

    private static void PruneLiveBannersLocked()
    {
        LivePersistentBanners.RemoveAll(w => !w.TryGetTarget(out _));
    }
}

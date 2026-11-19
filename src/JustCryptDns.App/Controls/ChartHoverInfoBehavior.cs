using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using JustCryptDns.App.Localization;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Pure eligibility rules for triggering the delayed hover explanation popup.
/// </summary>
public static class HoverDelayPolicy
{
    public const double DefaultDelaySeconds = 3.0;

    public static double ClampDelaySeconds(double seconds) =>
        double.IsNaN(seconds) || double.IsInfinity(seconds) ? DefaultDelaySeconds : Math.Clamp(seconds, 0.5, 30.0);

    public static bool ShouldTrigger(bool isMouseOver, bool isElementVisible, bool isHostVisible, bool isHostMinimized) =>
        isMouseOver && isElementVisible && isHostVisible && !isHostMinimized;
}

/// <summary>
/// Attached behavior showing a themed explanation popup when the user hovers over a chart or gauge
/// for at least <see cref="DelaySecondsProperty"/> seconds (default 3 seconds) without resetting on minor cursor movement.
/// </summary>
public static class ChartHoverInfoBehavior
{
    public static readonly DependencyProperty TitleProperty = DependencyProperty.RegisterAttached(
        "Title",
        typeof(string),
        typeof(ChartHoverInfoBehavior),
        new PropertyMetadata(string.Empty, OnContentPropertyChanged));

    public static readonly DependencyProperty DescriptionProperty = DependencyProperty.RegisterAttached(
        "Description",
        typeof(string),
        typeof(ChartHoverInfoBehavior),
        new PropertyMetadata(string.Empty, OnContentPropertyChanged));

    public static readonly DependencyProperty MetricsMeaningProperty = DependencyProperty.RegisterAttached(
        "MetricsMeaning",
        typeof(string),
        typeof(ChartHoverInfoBehavior),
        new PropertyMetadata(string.Empty, OnContentPropertyChanged));

    public static readonly DependencyProperty DelaySecondsProperty = DependencyProperty.RegisterAttached(
        "DelaySeconds",
        typeof(double),
        typeof(ChartHoverInfoBehavior),
        new PropertyMetadata(HoverDelayPolicy.DefaultDelaySeconds, OnContentPropertyChanged));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(HoverController),
        typeof(ChartHoverInfoBehavior),
        new PropertyMetadata(null));

    public static string GetTitle(DependencyObject obj) => (string)obj.GetValue(TitleProperty);

    public static void SetTitle(DependencyObject obj, string value) => obj.SetValue(TitleProperty, value);

    public static string GetDescription(DependencyObject obj) => (string)obj.GetValue(DescriptionProperty);

    public static void SetDescription(DependencyObject obj, string value) => obj.SetValue(DescriptionProperty, value);

    public static string GetMetricsMeaning(DependencyObject obj) => (string)obj.GetValue(MetricsMeaningProperty);

    public static void SetMetricsMeaning(DependencyObject obj, string value) => obj.SetValue(MetricsMeaningProperty, value);

    public static double GetDelaySeconds(DependencyObject obj) => (double)obj.GetValue(DelaySecondsProperty);

    public static void SetDelaySeconds(DependencyObject obj, double value) => obj.SetValue(DelaySecondsProperty, value);

    private static void OnContentPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement element)
        {
            return;
        }

        var hasContent = !string.IsNullOrWhiteSpace(GetTitle(element)) || !string.IsNullOrWhiteSpace(GetDescription(element));
        var controller = (HoverController?)element.GetValue(ControllerProperty);

        if (hasContent && controller is null)
        {
            controller = new HoverController(element);
            element.SetValue(ControllerProperty, controller);
        }
        else if (!hasContent && controller is not null)
        {
            controller.Detach();
            element.ClearValue(ControllerProperty);
        }
        else
        {
            controller?.UpdateDelay();
        }
    }

    private sealed class HoverController
    {
        private readonly FrameworkElement _element;
        private readonly DispatcherTimer _timer;
        private ToolTip? _toolTip;
        private Window? _hookedWindow;

        public HoverController(FrameworkElement element)
        {
            _element = element;
            ToolTipService.SetIsEnabled(_element, false);

            _timer = new DispatcherTimer(DispatcherPriority.Normal, element.Dispatcher)
            {
                Interval = TimeSpan.FromSeconds(HoverDelayPolicy.ClampDelaySeconds(GetDelaySeconds(element))),
            };
            _timer.Tick += OnTimerTick;

            _element.MouseEnter += OnMouseEnter;
            _element.MouseLeave += OnMouseLeave;
            _element.PreviewMouseDown += OnMouseDown;
            _element.IsVisibleChanged += OnElementVisibilityChanged;
            _element.Unloaded += OnUnloaded;
        }

        public void UpdateDelay()
        {
            _timer.Interval = TimeSpan.FromSeconds(HoverDelayPolicy.ClampDelaySeconds(GetDelaySeconds(_element)));
        }

        public void Detach()
        {
            DismissPopup();
            _element.MouseEnter -= OnMouseEnter;
            _element.MouseLeave -= OnMouseLeave;
            _element.PreviewMouseDown -= OnMouseDown;
            _element.IsVisibleChanged -= OnElementVisibilityChanged;
            _element.Unloaded -= OnUnloaded;
        }

        private void OnMouseEnter(object sender, MouseEventArgs e)
        {
            UpdateDelay();
            _timer.Stop();
            _timer.Start();
        }

        private void OnMouseLeave(object sender, MouseEventArgs e) => DismissPopup();

        private void OnMouseDown(object sender, MouseButtonEventArgs e) => DismissPopup();

        private void OnElementVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (e.NewValue is false)
            {
                DismissPopup();
            }
        }

        private void OnUnloaded(object sender, RoutedEventArgs e) => DismissPopup();

        private void OnTimerTick(object? sender, EventArgs e)
        {
            _timer.Stop();

            var host = Window.GetWindow(_element);
            if (!HoverDelayPolicy.ShouldTrigger(
                    _element.IsMouseOver,
                    _element.IsVisible,
                    host is null || host.IsVisible,
                    host?.WindowState == WindowState.Minimized))
            {
                return;
            }

            ShowPopup(host);
        }

        private void ShowPopup(Window? host)
        {
            var title = GetTitle(_element);
            var description = GetDescription(_element);
            var meaning = (GetMetricsMeaning(_element) ?? string.Empty).Replace("\\n", Environment.NewLine, StringComparison.Ordinal);

            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(description))
            {
                return;
            }

            var panel = new StackPanel { MaxWidth = 330 };

            var header = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            var icon = new TextBlock
            {
                Text = "\uE946",
                FontSize = 14,
                Margin = new Thickness(0, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center,
            };
            icon.SetResourceReference(TextBlock.FontFamilyProperty, "Font.Icons");
            icon.SetResourceReference(TextBlock.ForegroundProperty, "Brush.Accent");
            header.Children.Add(icon);

            var titleBlock = new TextBlock
            {
                Text = title,
                FontWeight = FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 300,
                VerticalAlignment = VerticalAlignment.Center,
            };
            titleBlock.SetResourceReference(TextBlock.ForegroundProperty, "Brush.TextPrimary");
            header.Children.Add(titleBlock);
            panel.Children.Add(header);

            if (!string.IsNullOrWhiteSpace(description))
            {
                var descBlock = new TextBlock
                {
                    Text = description,
                    TextWrapping = TextWrapping.Wrap,
                };
                descBlock.SetResourceReference(TextBlock.ForegroundProperty, "Brush.TextSecondary");
                panel.Children.Add(descBlock);
            }

            if (!string.IsNullOrWhiteSpace(meaning))
            {
                var divider = new Border { Height = 1, Margin = new Thickness(0, 8, 0, 8) };
                divider.SetResourceReference(Border.BackgroundProperty, "Brush.Divider");
                panel.Children.Add(divider);

                var labelBlock = new TextBlock
                {
                    Text = LocalizationManager.Instance["Dash_Explain_MeaningLabel"],
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 0, 0, 4),
                };
                labelBlock.SetResourceReference(TextBlock.FontSizeProperty, "Font.Size.Small");
                labelBlock.SetResourceReference(TextBlock.ForegroundProperty, "Brush.AccentText");
                panel.Children.Add(labelBlock);

                var meaningBlock = new TextBlock
                {
                    Text = meaning,
                    TextWrapping = TextWrapping.Wrap,
                };
                meaningBlock.SetResourceReference(TextBlock.ForegroundProperty, "Brush.TextPrimary");
                panel.Children.Add(meaningBlock);
            }

            _toolTip ??= new ToolTip
            {
                Placement = PlacementMode.Bottom,
                VerticalOffset = 6,
                StaysOpen = true,
            };
            _toolTip.PlacementTarget = _element;
            _toolTip.Content = panel;

            HookWindow(host);
            _toolTip.IsOpen = true;
        }

        private void HookWindow(Window? host)
        {
            if (ReferenceEquals(_hookedWindow, host))
            {
                return;
            }

            UnhookWindow();
            if (host is null)
            {
                return;
            }

            _hookedWindow = host;
            _hookedWindow.Deactivated += OnHostDeactivated;
            _hookedWindow.StateChanged += OnHostStateChanged;
            _hookedWindow.LocationChanged += OnHostMoved;
            _hookedWindow.IsVisibleChanged += OnHostVisibilityChanged;
        }

        private void UnhookWindow()
        {
            if (_hookedWindow is null)
            {
                return;
            }

            _hookedWindow.Deactivated -= OnHostDeactivated;
            _hookedWindow.StateChanged -= OnHostStateChanged;
            _hookedWindow.LocationChanged -= OnHostMoved;
            _hookedWindow.IsVisibleChanged -= OnHostVisibilityChanged;
            _hookedWindow = null;
        }

        private void OnHostDeactivated(object? sender, EventArgs e) => DismissPopup();

        private void OnHostMoved(object? sender, EventArgs e) => DismissPopup();

        private void OnHostStateChanged(object? sender, EventArgs e)
        {
            if (_hookedWindow?.WindowState == WindowState.Minimized)
            {
                DismissPopup();
            }
        }

        private void OnHostVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (e.NewValue is false)
            {
                DismissPopup();
            }
        }

        private void DismissPopup()
        {
            _timer.Stop();
            UnhookWindow();
            if (_toolTip is not null)
            {
                _toolTip.IsOpen = false;
            }
        }
    }
}

using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using JustCryptDns.App.Localization;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Attached behavior for inline copy buttons: copies <see cref="CopyTextProperty"/> to Clipboard
/// and briefly shows a success checkmark feedback without requiring per-ViewModel commands.
/// </summary>
public static class CopyTextBehavior
{
    private sealed record SavedButtonState(object? Content, object LocalForeground);

    public static readonly DependencyProperty CopyTextProperty = DependencyProperty.RegisterAttached(
        "CopyText",
        typeof(string),
        typeof(CopyTextBehavior),
        new PropertyMetadata(null, OnCopyTextChanged));

    private static readonly DependencyProperty ResetTimerProperty = DependencyProperty.RegisterAttached(
        "ResetTimer",
        typeof(DispatcherTimer),
        typeof(CopyTextBehavior),
        new PropertyMetadata(null));

    private static readonly DependencyProperty SavedStateProperty = DependencyProperty.RegisterAttached(
        "SavedState",
        typeof(SavedButtonState),
        typeof(CopyTextBehavior),
        new PropertyMetadata(null));

    public static string? GetCopyText(DependencyObject obj) => (string?)obj.GetValue(CopyTextProperty);

    public static void SetCopyText(DependencyObject obj, string? value) => obj.SetValue(CopyTextProperty, value);

    private static void OnCopyTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not Button button)
        {
            return;
        }

        button.Click -= OnCopyButtonClick;
        button.Unloaded -= OnButtonUnloaded;

        if (e.NewValue is not null)
        {
            button.Click += OnCopyButtonClick;
            button.Unloaded += OnButtonUnloaded;
            if (button.ToolTip is null)
            {
                button.ToolTip = LocalizationManager.Instance["Common_Copy"];
            }
        }
    }

    private static void OnButtonUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.GetValue(ResetTimerProperty) is DispatcherTimer timer)
        {
            timer.Stop();
            RestoreVisualState(button);
        }
    }

    private static void OnCopyButtonClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button)
        {
            return;
        }

        var text = GetCopyText(button);
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        try
        {
            Clipboard.SetText(text);
        }
        catch (ExternalException)
        {
            return;
        }

        if (button.GetValue(ResetTimerProperty) is DispatcherTimer existingTimer)
        {
            existingTimer.Stop();
        }
        else
        {
            button.SetValue(
                SavedStateProperty,
                new SavedButtonState(button.Content, button.ReadLocalValue(Control.ForegroundProperty)));
        }

        button.Content = "\uE73E";
        button.SetResourceReference(Control.ForegroundProperty, "Brush.Success");
        button.ToolTip = LocalizationManager.Instance["Common_Copied"];

        var resetTimer = new DispatcherTimer(DispatcherPriority.Normal, button.Dispatcher)
        {
            Interval = TimeSpan.FromSeconds(1.5),
        };
        resetTimer.Tick += (_, _) =>
        {
            resetTimer.Stop();
            RestoreVisualState(button);
        };
        button.SetValue(ResetTimerProperty, resetTimer);
        resetTimer.Start();
    }

    private static void RestoreVisualState(Button button)
    {
        if (button.GetValue(SavedStateProperty) is SavedButtonState saved)
        {
            button.Content = saved.Content;
            if (Equals(saved.LocalForeground, DependencyProperty.UnsetValue))
            {
                button.ClearValue(Control.ForegroundProperty);
            }
            else
            {
                button.SetValue(Control.ForegroundProperty, saved.LocalForeground);
            }
        }

        button.ToolTip = LocalizationManager.Instance["Common_Copy"];
        button.ClearValue(ResetTimerProperty);
        button.ClearValue(SavedStateProperty);
    }
}

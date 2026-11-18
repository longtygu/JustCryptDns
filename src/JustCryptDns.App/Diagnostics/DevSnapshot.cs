using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using JustCryptDns.App.ViewModels;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Diagnostics;

/// <summary>
/// Developer diagnostics: when <c>JUSTCRYPTDNS_SNAPSHOT_DIR</c> is set, renders each requested page of the main window
/// to PNG in-process (no desktop capture needed). Pages come from <c>JUSTCRYPTDNS_SNAPSHOT_PAGES</c> (comma separated keys).
/// Inactive unless the environment variable is present.
/// </summary>
internal static class DevSnapshot
{
    public static void TryAttach(Window window, ShellViewModel shell, ILogger logger)
    {
        var dir = Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_DIR");
        if (string.IsNullOrWhiteSpace(dir))
        {
            return;
        }

        var pages = (Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_PAGES") ?? PageKeys.Dashboard)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var suffix = Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_SUFFIX") ?? string.Empty;

        window.ContentRendered += async (_, _) =>
        {
            Directory.CreateDirectory(dir);
            foreach (var raw in pages)
            {
                var scrollBottom = raw.EndsWith(":bottom", StringComparison.OrdinalIgnoreCase);
                var page = scrollBottom ? raw[..^7] : raw;
                shell.NavigateTo(page);
                await Task.Delay(1500); // allow async data + transition to settle
                if (scrollBottom)
                {
                    FindScrollViewer(window)?.ScrollToEnd();
                }

                await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                var tag = scrollBottom ? "-bottom" : string.Empty;
                var path = Path.Combine(dir, $"{page}{tag}{suffix}.png");
                Save(window, path);
                logger.LogInformation("Dev snapshot written: {Path}", path);
            }
        };
    }

    private static System.Windows.Controls.ScrollViewer? FindScrollViewer(DependencyObject root)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is System.Windows.Controls.ScrollViewer sv && sv.ScrollableHeight > 0)
            {
                return sv;
            }

            if (FindScrollViewer(child) is { } nested)
            {
                return nested;
            }
        }

        return null;
    }

    private static void Save(Window window, string path)
    {
        if (window.Content is not FrameworkElement root)
        {
            return;
        }

        var dpi = VisualTreeHelper.GetDpi(window);
        var width = (int)Math.Ceiling(root.ActualWidth * dpi.DpiScaleX);
        var height = (int)Math.Ceiling(root.ActualHeight * dpi.DpiScaleY);
        var bitmap = new RenderTargetBitmap(width, height, dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);

        // Paint the window background first (it belongs to the Window, not the root element).
        // When the window background is translucent, composite over a synthetic wallpaper gradient
        // so automated PNG snapshots show the surface opacity hierarchy clearly.
        var rect = new Rect(0, 0, root.ActualWidth, root.ActualHeight);
        var visual = new DrawingVisual();
        using (var context = visual.RenderOpen())
        {
            if (window.Background is SolidColorBrush { Color.A: < 255 })
            {
                var wallpaper = new LinearGradientBrush(
                    Color.FromRgb(0x1E, 0x3A, 0x8A),
                    Color.FromRgb(0x6D, 0x28, 0xD9),
                    new Point(0, 0),
                    new Point(1, 1));
                context.DrawRectangle(wallpaper, null, rect);
            }

            context.DrawRectangle(window.Background, null, rect);
            context.DrawRectangle(new VisualBrush(root), null, rect);
        }

        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }
}

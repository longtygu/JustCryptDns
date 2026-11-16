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
            foreach (var page in pages)
            {
                shell.NavigateTo(page);
                await Task.Delay(1500); // allow async data + transition to settle
                await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                var path = Path.Combine(dir, $"{page}{suffix}.png");
                Save(window, path);
                logger.LogInformation("Dev snapshot written: {Path}", path);
            }
        };
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
        var visual = new DrawingVisual();
        using (var context = visual.RenderOpen())
        {
            context.DrawRectangle(window.Background, null, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
            context.DrawRectangle(new VisualBrush(root), null, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
        }

        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }
}

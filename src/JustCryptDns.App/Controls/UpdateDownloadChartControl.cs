using System.Globalization;
using System.Windows;
using System.Windows.Media;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Displays a live download throughput waveform alongside a 0–100% progress bar
/// inside the Software Updates section of Settings.
/// </summary>
public sealed class UpdateDownloadChartControl : FrameworkElement
{
    private const int MaxSamples = 60;

    public static readonly DependencyProperty AccentBrushProperty = DependencyProperty.Register(
        nameof(AccentBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TrackBrushProperty = DependencyProperty.Register(
        nameof(TrackBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.DimGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty GridBrushProperty = DependencyProperty.Register(
        nameof(GridBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.DimGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SurfaceBrushProperty = DependencyProperty.Register(
        nameof(SurfaceBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.Black, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty BorderBrushProperty = DependencyProperty.Register(
        nameof(BorderBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TextBrushProperty = DependencyProperty.Register(
        nameof(TextBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.White, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SecondaryTextBrushProperty = DependencyProperty.Register(
        nameof(SecondaryTextBrush),
        typeof(Brush),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(Brushes.LightGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ProgressPercentProperty = DependencyProperty.Register(
        nameof(ProgressPercent),
        typeof(double),
        typeof(UpdateDownloadChartControl),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    private static readonly Typeface ScaleTypeface = new(
        new FontFamily("Segoe UI Variable Text, Segoe UI"),
        FontStyles.Normal,
        FontWeights.Medium,
        FontStretches.Normal);

    private readonly List<double> _speedSamples = new(MaxSamples + 4);
    private double _smoothedCeilingBps = 256 * 1024;
    private double _latestSpeedBps;

    public UpdateDownloadChartControl()
    {
        IsHitTestVisible = false;
        ClipToBounds = true;
        MinHeight = 136;
    }

    public Brush AccentBrush
    {
        get => (Brush)GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    public Brush TrackBrush
    {
        get => (Brush)GetValue(TrackBrushProperty);
        set => SetValue(TrackBrushProperty, value);
    }

    public Brush GridBrush
    {
        get => (Brush)GetValue(GridBrushProperty);
        set => SetValue(GridBrushProperty, value);
    }

    public Brush SurfaceBrush
    {
        get => (Brush)GetValue(SurfaceBrushProperty);
        set => SetValue(SurfaceBrushProperty, value);
    }

    public Brush BorderBrush
    {
        get => (Brush)GetValue(BorderBrushProperty);
        set => SetValue(BorderBrushProperty, value);
    }

    public Brush TextBrush
    {
        get => (Brush)GetValue(TextBrushProperty);
        set => SetValue(TextBrushProperty, value);
    }

    public Brush SecondaryTextBrush
    {
        get => (Brush)GetValue(SecondaryTextBrushProperty);
        set => SetValue(SecondaryTextBrushProperty, value);
    }

    public double ProgressPercent
    {
        get => (double)GetValue(ProgressPercentProperty);
        set => SetValue(ProgressPercentProperty, value);
    }

    public void Reset()
    {
        _speedSamples.Clear();
        _smoothedCeilingBps = 256 * 1024;
        _latestSpeedBps = 0;
        ProgressPercent = 0;
        InvalidateVisual();
    }

    public void PushSample(UpdateDownloadProgress progress)
    {
        ArgumentNullException.ThrowIfNull(progress);
        ProgressPercent = Math.Clamp(progress.ProgressPercent, 0.0, 100.0);
        _latestSpeedBps = Math.Max(0.0, progress.InstantBytesPerSecond);
        _speedSamples.Add(_latestSpeedBps);
        if (_speedSamples.Count > MaxSamples)
        {
            _speedSamples.RemoveRange(0, _speedSamples.Count - MaxSamples);
        }

        var peak = _speedSamples.Count > 0 ? _speedSamples.Max() : 0.0;
        var targetCeiling = Math.Max(128 * 1024.0, peak * 1.25);
        _smoothedCeilingBps = (_smoothedCeilingBps * 0.65) + (targetCeiling * 0.35);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        var w = ActualWidth;
        var h = ActualHeight;
        if (w < 140 || h < 96)
        {
            return;
        }

        var accentColor = ExtractColor(AccentBrush, Color.FromRgb(0x4F, 0x8C, 0xFF));
        var trackColor = ExtractColor(TrackBrush, Color.FromRgb(0x2F, 0x35, 0x42));
        var gridColor = ExtractColor(GridBrush, Color.FromRgb(0x2A, 0x2F, 0x3A));
        var surfaceColor = ExtractColor(SurfaceBrush, Color.FromRgb(0x14, 0x17, 0x1E));
        var borderColor = ExtractColor(BorderBrush, Color.FromRgb(0x28, 0x2D, 0x38));

        var outerRect = new Rect(0.5, 0.5, w - 1.0, h - 1.0);
        var bezelBrush = new LinearGradientBrush(
            WithAlpha(surfaceColor, 0.85),
            WithAlpha(surfaceColor, 0.45),
            90.0);
        bezelBrush.Freeze();
        var bezelPen = new Pen(FrozenBrush(WithAlpha(borderColor, 0.75)), 1.0);
        bezelPen.Freeze();
        drawingContext.DrawRoundedRectangle(bezelBrush, bezelPen, outerRect, 8.0, 8.0);

        const double marginLeft = 64.0;
        const double marginRight = 16.0;
        const double marginTop = 14.0;
        const double progressBandHeight = 28.0;
        var plotWidth = Math.Max(40.0, w - marginLeft - marginRight);
        var plotHeight = Math.Max(36.0, h - marginTop - progressBandHeight - 10.0);
        var plotRect = new Rect(marginLeft, marginTop, plotWidth, plotHeight);

        DrawHorizontalGrid(drawingContext, plotRect, gridColor);
        DrawSpeedCurve(drawingContext, plotRect, accentColor);
        DrawProgressBar(drawingContext, w, h - progressBandHeight, marginLeft, marginRight, accentColor, trackColor);
    }

    private void DrawHorizontalGrid(DrawingContext dc, Rect plotRect, Color gridColor)
    {
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var gridPen = new Pen(FrozenBrush(WithAlpha(gridColor, 0.45)), 1.0) { DashStyle = DashStyles.Dash };
        gridPen.Freeze();

        for (var i = 0; i <= 2; i++)
        {
            var ratio = i / 2.0;
            var y = plotRect.Bottom - (ratio * plotRect.Height);
            dc.DrawLine(gridPen, new Point(plotRect.Left, y), new Point(plotRect.Right, y));

            var labelText = FormatSpeed(_smoothedCeilingBps * ratio);
            var ft = new FormattedText(labelText, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, ScaleTypeface, 10.5, SecondaryTextBrush, dpi);
            dc.DrawText(ft, new Point(10.0, Math.Max(4.0, y - (ft.Height * 0.5))));
        }
    }

    private void DrawSpeedCurve(DrawingContext dc, Rect plotRect, Color accentColor)
    {
        if (_speedSamples.Count == 0)
        {
            var midY = plotRect.Bottom - 2.0;
            var idlePen = new Pen(FrozenBrush(WithAlpha(accentColor, 0.45)), 1.5);
            idlePen.Freeze();
            dc.DrawLine(idlePen, new Point(plotRect.Left, midY), new Point(plotRect.Right, midY));
            return;
        }

        var clip = new RectangleGeometry(plotRect);
        clip.Freeze();
        dc.PushClip(clip);
        try
        {
            var count = _speedSamples.Count;
            var stepX = plotRect.Width / Math.Max(1, MaxSamples - 1);
            var startX = count >= MaxSamples
                ? plotRect.Left
                : plotRect.Right - ((count - 1) * stepX);

            var points = new Point[count];
            for (var i = 0; i < count; i++)
            {
                var norm = Math.Clamp(_speedSamples[i] / Math.Max(1.0, _smoothedCeilingBps), 0.0, 1.0);
                var x = startX + (i * stepX);
                var y = plotRect.Bottom - (norm * (plotRect.Height - 4.0)) - 2.0;
                points[i] = new Point(x, y);
            }

            if (points.Length >= 2)
            {
                var fillGeom = new StreamGeometry();
                using (var ctx = fillGeom.Open())
                {
                    ctx.BeginFigure(new Point(points[0].X, plotRect.Bottom), isFilled: true, isClosed: true);
                    ctx.LineTo(points[0], isStroked: false, isSmoothJoin: false);
                    for (var i = 1; i < points.Length; i++)
                    {
                        ctx.LineTo(points[i], isStroked: false, isSmoothJoin: true);
                    }
                    ctx.LineTo(new Point(points[^1].X, plotRect.Bottom), isStroked: false, isSmoothJoin: false);
                }
                fillGeom.Freeze();

                var areaBrush = new LinearGradientBrush(
                    WithAlpha(accentColor, 0.34),
                    WithAlpha(accentColor, 0.03),
                    90.0);
                areaBrush.Freeze();
                dc.DrawGeometry(areaBrush, null, fillGeom);

                var strokeGeom = new StreamGeometry();
                using (var ctx = strokeGeom.Open())
                {
                    ctx.BeginFigure(points[0], isFilled: false, isClosed: false);
                    for (var i = 1; i < points.Length; i++)
                    {
                        ctx.LineTo(points[i], isStroked: true, isSmoothJoin: true);
                    }
                }
                strokeGeom.Freeze();

                var glowPen = new Pen(FrozenBrush(WithAlpha(accentColor, 0.30)), 5.0)
                {
                    StartLineCap = PenLineCap.Round,
                    EndLineCap = PenLineCap.Round,
                    LineJoin = PenLineJoin.Round,
                };
                glowPen.Freeze();
                dc.DrawGeometry(null, glowPen, strokeGeom);

                var linePen = new Pen(FrozenBrush(accentColor), 2.2)
                {
                    StartLineCap = PenLineCap.Round,
                    EndLineCap = PenLineCap.Round,
                    LineJoin = PenLineJoin.Round,
                };
                linePen.Freeze();
                dc.DrawGeometry(null, linePen, strokeGeom);
            }

            var head = points[^1];
            dc.DrawEllipse(FrozenBrush(WithAlpha(accentColor, 0.28)), null, head, 6.0, 6.0);
            dc.DrawEllipse(FrozenBrush(accentColor), null, head, 3.0, 3.0);
        }
        finally
        {
            dc.Pop();
        }
    }

    private void DrawProgressBar(
        DrawingContext dc,
        double totalWidth,
        double topY,
        double marginLeft,
        double marginRight,
        Color accentColor,
        Color trackColor)
    {
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var pct = Math.Clamp(ProgressPercent, 0.0, 100.0);
        var pctText = $"{pct:0.0}%";
        var ft = new FormattedText(pctText, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, ScaleTypeface, 11.5, TextBrush, dpi);

        var barWidth = Math.Max(40.0, totalWidth - marginLeft - marginRight - ft.Width - 12.0);
        var barRect = new Rect(marginLeft, topY + 7.0, barWidth, 8.0);
        dc.DrawRoundedRectangle(FrozenBrush(WithAlpha(trackColor, 0.7)), null, barRect, 4.0, 4.0);

        var fillWidth = barWidth * (pct / 100.0);
        if (fillWidth > 1.0)
        {
            var fillRect = new Rect(barRect.Left, barRect.Top, fillWidth, barRect.Height);
            var fillBrush = new LinearGradientBrush(accentColor, WithAlpha(accentColor, 0.8), 0.0);
            fillBrush.Freeze();
            dc.DrawRoundedRectangle(fillBrush, null, fillRect, 4.0, 4.0);
        }

        dc.DrawText(ft, new Point(barRect.Right + 10.0, topY + 2.0));
    }

    public static string FormatSpeed(double bytesPerSecond)
    {
        if (bytesPerSecond <= 0)
        {
            return "0 KB/s";
        }

        if (bytesPerSecond >= 1024 * 1024)
        {
            return $"{bytesPerSecond / (1024.0 * 1024.0):0.0} MB/s";
        }

        return $"{bytesPerSecond / 1024.0:0} KB/s";
    }

    private static Color ExtractColor(Brush? brush, Color fallback) =>
        brush is SolidColorBrush solid ? solid.Color : fallback;

    private static Color WithAlpha(Color color, double opacity)
    {
        var a = (byte)Math.Clamp((int)Math.Round(color.A * opacity), 0, 255);
        return Color.FromArgb(a, color.R, color.G, color.B);
    }

    private static SolidColorBrush FrozenBrush(Color color)
    {
        var b = new SolidColorBrush(color);
        b.Freeze();
        return b;
    }
}

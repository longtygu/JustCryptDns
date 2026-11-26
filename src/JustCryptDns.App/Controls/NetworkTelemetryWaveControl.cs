using System.Globalization;
using System.Windows;
using System.Windows.Media;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Full-width automotive instrument waveform chart displaying continuous horizontal scrolling curves
/// for live ICMP Ping (ms) and Network Throughput (Download & Upload speed).
/// </summary>
public sealed class NetworkTelemetryWaveControl : FrameworkElement
{
    private const int VisibleSlots = 48;

    public static readonly DependencyProperty PingBrushProperty = DependencyProperty.Register(
        nameof(PingBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.Goldenrod, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty DownloadBrushProperty = DependencyProperty.Register(
        nameof(DownloadBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty UploadBrushProperty = DependencyProperty.Register(
        nameof(UploadBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.MediumSeaGreen, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty GridBrushProperty = DependencyProperty.Register(
        nameof(GridBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.DimGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SurfaceBrushProperty = DependencyProperty.Register(
        nameof(SurfaceBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.Black, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty BorderBrushProperty = DependencyProperty.Register(
        nameof(BorderBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TextBrushProperty = DependencyProperty.Register(
        nameof(TextBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.White, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SecondaryTextBrushProperty = DependencyProperty.Register(
        nameof(SecondaryTextBrush),
        typeof(Brush),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty IsPausedProperty = DependencyProperty.Register(
        nameof(IsPaused),
        typeof(bool),
        typeof(NetworkTelemetryWaveControl),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    private static readonly Typeface ScaleTypeface = new(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, FontWeights.Medium, FontStretches.Normal);
    private readonly List<NetworkTelemetrySample> _samples = new(64);
    private double _scrollPhase;
    private double _animTime;
    private double _smoothedPingCeiling = 50.0;
    private double _smoothedSpeedCeiling = 1.0;

    public NetworkTelemetryWaveControl()
    {
        IsHitTestVisible = false;
        ClipToBounds = true;
        MinHeight = 160;
    }

    public Brush PingBrush
    {
        get => (Brush)GetValue(PingBrushProperty);
        set => SetValue(PingBrushProperty, value);
    }

    public Brush DownloadBrush
    {
        get => (Brush)GetValue(DownloadBrushProperty);
        set => SetValue(DownloadBrushProperty, value);
    }

    public Brush UploadBrush
    {
        get => (Brush)GetValue(UploadBrushProperty);
        set => SetValue(UploadBrushProperty, value);
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

    public bool IsPaused
    {
        get => (bool)GetValue(IsPausedProperty);
        set => SetValue(IsPausedProperty, value);
    }

    public void SetSamples(IReadOnlyList<NetworkTelemetrySample> samples)
    {
        _samples.Clear();
        if (samples is not null && samples.Count > 0)
        {
            var skip = Math.Max(0, samples.Count - VisibleSlots);
            for (var i = skip; i < samples.Count; i++)
            {
                _samples.Add(samples[i]);
            }
        }

        _scrollPhase = 0.0;
        RecalculateTargets(snap: true);
        InvalidateVisual();
    }

    public void AddSample(NetworkTelemetrySample sample)
    {
        _samples.Add(sample);
        if (_samples.Count > VisibleSlots + 4)
        {
            _samples.RemoveRange(0, _samples.Count - (VisibleSlots + 4));
        }

        _scrollPhase = 0.0;
        RecalculateTargets(snap: false);
        InvalidateVisual();
    }

    public void StepFrame(double dtSeconds)
    {
        _animTime += dtSeconds;
        _scrollPhase = Math.Min(1.0, _scrollPhase + dtSeconds);
        RecalculateTargets(snap: false, dtSeconds: dtSeconds);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        var w = ActualWidth;
        var h = ActualHeight;
        if (w < 140 || h < 80)
        {
            return;
        }

        var pingColor = ExtractColor(PingBrush, Color.FromRgb(0xF5, 0xB9, 0x46));
        var downColor = ExtractColor(DownloadBrush, Color.FromRgb(0x4F, 0x8C, 0xFF));
        var upColor = ExtractColor(UploadBrush, Color.FromRgb(0x3D, 0xD6, 0x8C));
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

        const double marginLeft = 52.0;
        const double marginRight = 64.0;
        const double marginTop = 14.0;
        const double marginBottom = 16.0;
        var plotWidth = Math.Max(40.0, w - marginLeft - marginRight);
        var plotHeight = Math.Max(30.0, h - marginTop - marginBottom);
        var plotRect = new Rect(marginLeft, marginTop, plotWidth, plotHeight);

        DrawAxesAndGrid(drawingContext, plotRect, pingColor, downColor, gridColor);

        var clip = new RectangleGeometry(plotRect);
        clip.Freeze();
        drawingContext.PushClip(clip);
        try
        {
            DrawVerticalSweepGrid(drawingContext, plotRect, gridColor);

            if (_samples.Count < 2)
            {
                DrawIdleCarrierWave(drawingContext, plotRect, downColor, upColor, pingColor);
            }
            else
            {
                var stepX = plotRect.Width / (VisibleSlots - 1);
                DrawSeries(
                    drawingContext,
                    plotRect,
                    stepX,
                    s => s.DownloadMbps,
                    _smoothedSpeedCeiling,
                    downColor,
                    fillAlpha: 0.22,
                    strokeThickness: 2.2,
                    drawGlow: true);

                DrawSeries(
                    drawingContext,
                    plotRect,
                    stepX,
                    s => s.UploadMbps,
                    _smoothedSpeedCeiling,
                    upColor,
                    fillAlpha: 0.12,
                    strokeThickness: 1.6,
                    drawGlow: false);

                DrawSeries(
                    drawingContext,
                    plotRect,
                    stepX,
                    s => s.PingMs,
                    _smoothedPingCeiling,
                    pingColor,
                    fillAlpha: 0.14,
                    strokeThickness: 2.0,
                    drawGlow: true);
            }
        }
        finally
        {
            drawingContext.Pop();
        }
    }

    private void DrawAxesAndGrid(DrawingContext dc, Rect plot, Color pingColor, Color downColor, Color gridColor)
    {
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var dashPen = new Pen(FrozenBrush(WithAlpha(gridColor, 0.75)), 1.0)
        {
            DashStyle = new DashStyle([3.0, 4.0], 0.0),
        };
        dashPen.Freeze();

        var pingAxisBrush = FrozenBrush(WithAlpha(pingColor, 0.90));
        var speedAxisBrush = FrozenBrush(WithAlpha(downColor, 0.90));

        for (var row = 0; row <= 2; row++)
        {
            var fraction = row / 2.0; // 0 = top, 1 = bottom
            var y = plot.Top + (fraction * plot.Height);
            dc.DrawLine(dashPen, new Point(plot.Left, y), new Point(plot.Right, y));

            var scaleValue = 1.0 - fraction;
            var pingVal = Math.Round(_smoothedPingCeiling * scaleValue);
            var pingLabel = string.Create(CultureInfo.InvariantCulture, $"{pingVal:0} ms");
            var pingText = CreateFormattedText(pingLabel, ScaleTypeface, 9.5, pingAxisBrush, dpi);
            dc.DrawText(pingText, new Point(Math.Max(4.0, plot.Left - pingText.Width - 6.0), y - (pingText.Height / 2.0)));

            var speedMbps = _smoothedSpeedCeiling * scaleValue;
            var speedLabel = FormatSpeedAxis(speedMbps);
            var speedText = CreateFormattedText(speedLabel, ScaleTypeface, 9.5, speedAxisBrush, dpi);
            dc.DrawText(speedText, new Point(plot.Right + 6.0, y - (speedText.Height / 2.0)));
        }
    }

    private void DrawVerticalSweepGrid(DrawingContext dc, Rect plot, Color gridColor)
    {
        var stepX = plot.Width / (VisibleSlots - 1);
        const int intervalSamples = 6;
        var spacing = stepX * intervalSamples;
        var shift = _scrollPhase * stepX;

        var vPen = new Pen(FrozenBrush(WithAlpha(gridColor, 0.42)), 1.0);
        vPen.Freeze();

        for (var x = plot.Right - shift; x >= plot.Left; x -= spacing)
        {
            dc.DrawLine(vPen, new Point(x, plot.Top), new Point(x, plot.Bottom));
        }
    }

    private void DrawIdleCarrierWave(DrawingContext dc, Rect plot, Color downColor, Color upColor, Color pingColor)
    {
        var phase = IsPaused ? 0.0 : _animTime * 3.2;
        DrawSineBaseline(dc, plot, phase, downColor, plot.Bottom - 8.0, 2.5, 1.8);
        DrawSineBaseline(dc, plot, phase + 1.4, upColor, plot.Bottom - 4.0, 1.6, 1.3);
        DrawSineBaseline(dc, plot, phase + 2.7, pingColor, plot.Top + (plot.Height * 0.55), 2.2, 1.6);
    }

    private static void DrawSineBaseline(
        DrawingContext dc,
        Rect plot,
        double phase,
        Color color,
        double baseY,
        double amp,
        double strokeWidth)
    {
        const int segments = 32;
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            for (var i = 0; i <= segments; i++)
            {
                var t = i / (double)segments;
                var x = plot.Left + (t * plot.Width);
                var y = Math.Clamp(baseY + (Math.Sin((t * 14.0) - phase) * amp), plot.Top + 2.0, plot.Bottom - 2.0);
                if (i == 0)
                {
                    ctx.BeginFigure(new Point(x, y), isFilled: false, isClosed: false);
                }
                else
                {
                    ctx.LineTo(new Point(x, y), isStroked: true, isSmoothJoin: true);
                }
            }
        }
        geo.Freeze();

        var pen = new Pen(FrozenBrush(WithAlpha(color, 0.55)), strokeWidth);
        pen.Freeze();
        dc.DrawGeometry(null, pen, geo);
    }

    private void DrawSeries(
        DrawingContext dc,
        Rect plot,
        double stepX,
        Func<NetworkTelemetrySample, double?> selector,
        double ceiling,
        Color color,
        double fillAlpha,
        double strokeThickness,
        bool drawGlow)
    {
        var points = new List<Point>(_samples.Count);
        var count = _samples.Count;
        var safeCeiling = Math.Max(0.001, ceiling);

        for (var i = 0; i < count; i++)
        {
            var raw = selector(_samples[i]);
            if (raw is not { } value || double.IsNaN(value) || double.IsInfinity(value))
            {
                continue;
            }

            var x = plot.Right - (((count - 1 - i) + _scrollPhase) * stepX);
            if (x < plot.Left - stepX)
            {
                continue;
            }

            var norm = Math.Clamp(value / safeCeiling, 0.0, 1.0);
            var y = plot.Bottom - (norm * (plot.Height - 6.0)) - 2.0;
            points.Add(new Point(x, y));
        }

        if (points.Count == 0)
        {
            return;
        }

        if (points.Count == 1)
        {
            var p = points[0];
            dc.DrawEllipse(FrozenBrush(color), null, p, 3.2, 3.2);
            return;
        }

        var lineGeo = BuildSmoothCurveGeometry(points, closeToBottom: false, plot.Bottom);
        var areaGeo = BuildSmoothCurveGeometry(points, closeToBottom: true, plot.Bottom);

        var fillBrush = new LinearGradientBrush(
            WithAlpha(color, fillAlpha),
            WithAlpha(color, 0.0),
            90.0);
        fillBrush.Freeze();
        dc.DrawGeometry(fillBrush, null, areaGeo);

        if (drawGlow)
        {
            var glowPen = new Pen(FrozenBrush(WithAlpha(color, 0.22)), strokeThickness * 2.4)
            {
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round,
                LineJoin = PenLineJoin.Round,
            };
            glowPen.Freeze();
            dc.DrawGeometry(null, glowPen, lineGeo);
        }

        var strokePen = new Pen(FrozenBrush(color), strokeThickness)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round,
        };
        strokePen.Freeze();
        dc.DrawGeometry(null, strokePen, lineGeo);

        var latest = points[^1];
        var pulse = IsPaused ? 0.0 : (0.5 + (0.5 * Math.Sin(_animTime * 4.5)));
        dc.DrawEllipse(FrozenBrush(WithAlpha(color, 0.25 + (0.20 * pulse))), null, latest, 5.0 + (1.5 * pulse), 5.0 + (1.5 * pulse));
        dc.DrawEllipse(FrozenBrush(MixColor(color, Colors.White, 0.25)), null, latest, 2.8, 2.8);
    }

    private static StreamGeometry BuildSmoothCurveGeometry(List<Point> points, bool closeToBottom, double bottomY)
    {
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            if (closeToBottom)
            {
                ctx.BeginFigure(new Point(points[0].X, bottomY), isFilled: true, isClosed: true);
                ctx.LineTo(points[0], isStroked: false, isSmoothJoin: false);
            }
            else
            {
                ctx.BeginFigure(points[0], isFilled: false, isClosed: false);
            }

            if (points.Count == 2)
            {
                ctx.LineTo(points[1], isStroked: !closeToBottom, isSmoothJoin: true);
            }
            else
            {
                for (var i = 0; i < points.Count - 1; i++)
                {
                    var p0 = i == 0 ? points[0] : points[i - 1];
                    var p1 = points[i];
                    var p2 = points[i + 1];
                    var p3 = i + 2 < points.Count ? points[i + 2] : p2;

                    const double tension = 6.0;
                    var cp1 = new Point(p1.X + ((p2.X - p0.X) / tension), p1.Y + ((p2.Y - p0.Y) / tension));
                    var cp2 = new Point(p2.X - ((p3.X - p1.X) / tension), p2.Y - ((p3.Y - p1.Y) / tension));

                    var minY = Math.Min(p1.Y, p2.Y) - 6.0;
                    var maxY = bottomY;
                    cp1.Y = Math.Clamp(cp1.Y, Math.Max(2.0, minY), maxY);
                    cp2.Y = Math.Clamp(cp2.Y, Math.Max(2.0, minY), maxY);

                    ctx.BezierTo(cp1, cp2, p2, isStroked: !closeToBottom, isSmoothJoin: true);
                }
            }

            if (closeToBottom)
            {
                ctx.LineTo(new Point(points[^1].X, bottomY), isStroked: false, isSmoothJoin: false);
            }
        }

        geo.Freeze();
        return geo;
    }

    private void RecalculateTargets(bool snap, double dtSeconds = 0.033)
    {
        var pings = new List<double>(_samples.Count);
        var speeds = new List<double>(_samples.Count);

        for (var i = 0; i < _samples.Count; i++)
        {
            var s = _samples[i];
            if (s.PingMs is { } p)
            {
                pings.Add(p);
            }

            speeds.Add(Math.Max(s.DownloadMbps, s.UploadMbps));
        }

        var targetPing = GaugeMath.ComputePingWaveCeiling(pings);
        var targetSpeed = GaugeMath.ComputeSpeedWaveCeiling(speeds);

        if (snap)
        {
            _smoothedPingCeiling = targetPing;
            _smoothedSpeedCeiling = targetSpeed;
        }
        else
        {
            var alpha = 1.0 - Math.Exp(-4.0 * Math.Clamp(dtSeconds, 0.005, 0.25));
            _smoothedPingCeiling += (targetPing - _smoothedPingCeiling) * alpha;
            _smoothedSpeedCeiling += (targetSpeed - _smoothedSpeedCeiling) * alpha;
        }
    }

    private static string FormatSpeedAxis(double mbps)
    {
        if (mbps <= 0.001)
        {
            return "0";
        }

        if (mbps < 1.0)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{mbps * 1000.0:0} Kbps");
        }

        return string.Create(CultureInfo.InvariantCulture, $"{mbps:0.#} Mbps");
    }

    private static FormattedText CreateFormattedText(string text, Typeface typeface, double fontSize, Brush brush, double pixelsPerDip) =>
        new(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, typeface, fontSize, brush, pixelsPerDip);

    private static Color ExtractColor(Brush? brush, Color fallback) =>
        brush is SolidColorBrush scb ? scb.Color : fallback;

    private static Color WithAlpha(Color color, double alpha) =>
        Color.FromArgb((byte)Math.Round(Math.Clamp(alpha, 0.0, 1.0) * 255.0), color.R, color.G, color.B);

    private static Color MixColor(Color a, Color b, double amount) => Color.FromArgb(
        a.A,
        (byte)Math.Round(a.R + ((b.R - a.R) * amount)),
        (byte)Math.Round(a.G + ((b.G - a.G) * amount)),
        (byte)Math.Round(a.B + ((b.B - a.B) * amount)));

    private static SolidColorBrush FrozenBrush(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }
}

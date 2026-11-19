using System.Globalization;
using System.Windows;
using System.Windows.Media;

namespace JustCryptDns.App.Controls;

/// <summary>
/// Automotive-inspired 240-degree speedometer dial with tapered needle, dynamic ticks,
/// active traveling arc shimmer, and live micro-rev motion driven by DashboardView's shared timer.
/// </summary>
public sealed class SpeedometerGaugeControl : FrameworkElement
{
    private const double StartAngleDeg = 150.0;
    private const double SweepAngleDeg = 240.0;
    private const int TickIntervals = 20;

    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value),
        typeof(double),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender, OnValueChanged));

    public static readonly DependencyProperty MinimumProperty = DependencyProperty.Register(
        nameof(Minimum),
        typeof(double),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MaximumProperty = DependencyProperty.Register(
        nameof(Maximum),
        typeof(double),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(100.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ValueTextProperty = DependencyProperty.Register(
        nameof(ValueText),
        typeof(string),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata("—", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MaxScaleLabelProperty = DependencyProperty.Register(
        nameof(MaxScaleLabel),
        typeof(string),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata("100", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty AccentBrushProperty = DependencyProperty.Register(
        nameof(AccentBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TrackBrushProperty = DependencyProperty.Register(
        nameof(TrackBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.DimGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TextBrushProperty = DependencyProperty.Register(
        nameof(TextBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.White, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SecondaryTextBrushProperty = DependencyProperty.Register(
        nameof(SecondaryTextBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty DangerBrushProperty = DependencyProperty.Register(
        nameof(DangerBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.IndianRed, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty FaceBrushProperty = DependencyProperty.Register(
        nameof(FaceBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.Black, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty BorderBrushProperty = DependencyProperty.Register(
        nameof(BorderBrush),
        typeof(Brush),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty IsActiveProperty = DependencyProperty.Register(
        nameof(IsActive),
        typeof(bool),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ShowRedlineZoneProperty = DependencyProperty.Register(
        nameof(ShowRedlineZone),
        typeof(bool),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty PhaseOffsetProperty = DependencyProperty.Register(
        nameof(PhaseOffset),
        typeof(double),
        typeof(SpeedometerGaugeControl),
        new FrameworkPropertyMetadata(0.0));

    private static readonly Typeface DisplayTypeface = new(new FontFamily("Segoe UI Variable Display, Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
    private static readonly Typeface LabelTypeface = new(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, FontWeights.Medium, FontStretches.Normal);

    private double _displayedNormalized;
    private double _animTime;
    private double _pulseBoost;

    public SpeedometerGaugeControl()
    {
        IsHitTestVisible = false;
        SnapsToDevicePixels = false;
        MinHeight = 142;
    }

    public double Value
    {
        get => (double)GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    public double Minimum
    {
        get => (double)GetValue(MinimumProperty);
        set => SetValue(MinimumProperty, value);
    }

    public double Maximum
    {
        get => (double)GetValue(MaximumProperty);
        set => SetValue(MaximumProperty, value);
    }

    public string ValueText
    {
        get => (string)GetValue(ValueTextProperty);
        set => SetValue(ValueTextProperty, value);
    }

    public string MaxScaleLabel
    {
        get => (string)GetValue(MaxScaleLabelProperty);
        set => SetValue(MaxScaleLabelProperty, value);
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

    public Brush DangerBrush
    {
        get => (Brush)GetValue(DangerBrushProperty);
        set => SetValue(DangerBrushProperty, value);
    }

    public Brush FaceBrush
    {
        get => (Brush)GetValue(FaceBrushProperty);
        set => SetValue(FaceBrushProperty, value);
    }

    public Brush BorderBrush
    {
        get => (Brush)GetValue(BorderBrushProperty);
        set => SetValue(BorderBrushProperty, value);
    }

    public bool IsActive
    {
        get => (bool)GetValue(IsActiveProperty);
        set => SetValue(IsActiveProperty, value);
    }

    public bool ShowRedlineZone
    {
        get => (bool)GetValue(ShowRedlineZoneProperty);
        set => SetValue(ShowRedlineZoneProperty, value);
    }

    public double PhaseOffset
    {
        get => (double)GetValue(PhaseOffsetProperty);
        set => SetValue(PhaseOffsetProperty, value);
    }

    public void StepFrame(double dtSeconds)
    {
        _animTime += dtSeconds;
        if (_pulseBoost > 0.0)
        {
            _pulseBoost = Math.Max(0.0, _pulseBoost - (dtSeconds * 0.08));
        }

        var target = GaugeMath.ComputeNormalized(Value, Minimum, Maximum);
        _displayedNormalized = GaugeMath.StepNeedle(_displayedNormalized, target, dtSeconds);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        var w = ActualWidth;
        var h = ActualHeight;
        if (w < 60 || h < 60)
        {
            return;
        }

        var radius = Math.Clamp(Math.Min((w - 16.0) / 2.0, (h - 20.0) / 1.70), 34.0, 74.0);
        var cx = w / 2.0;
        var cy = Math.Max(radius + 8.0, h * 0.54);
        var arcThickness = Math.Clamp(radius * 0.125, 5.0, 9.0);

        var accentColor = ExtractColor(AccentBrush, Color.FromRgb(0x4F, 0x8C, 0xFF));
        var trackColor = ExtractColor(TrackBrush, Color.FromRgb(0x2A, 0x2F, 0x3A));
        var dangerColor = ExtractColor(DangerBrush, Color.FromRgb(0xFF, 0x6B, 0x6B));
        var faceColor = ExtractColor(FaceBrush, Color.FromRgb(0x18, 0x1B, 0x21));
        var borderColor = ExtractColor(BorderBrush, Color.FromRgb(0x32, 0x38, 0x44));
        var secTextColor = ExtractColor(SecondaryTextBrush, Color.FromRgb(0x88, 0x90, 0x9E));

        var visualNormalized = Math.Clamp(
            _displayedNormalized + GaugeMath.ComputeLiveIdleJitter(_animTime, _displayedNormalized, IsActive, PhaseOffset, _pulseBoost),
            0.0,
            1.0);

        DrawDialFace(drawingContext, cx, cy, radius, faceColor, borderColor, accentColor);
        DrawTrackAndRedline(drawingContext, cx, cy, radius, arcThickness, trackColor, dangerColor);
        DrawTickMarks(drawingContext, cx, cy, radius, arcThickness, visualNormalized, accentColor, dangerColor, secTextColor);
        DrawActiveArc(drawingContext, cx, cy, radius, arcThickness, visualNormalized, accentColor);
        DrawNeedleAndHub(drawingContext, cx, cy, radius, visualNormalized, accentColor, borderColor, faceColor);
        DrawScaleAndValueText(drawingContext, w, h, cx, cy, radius);
    }

    private void DrawDialFace(DrawingContext dc, double cx, double cy, double radius, Color faceColor, Color borderColor, Color accentColor)
    {
        var center = new Point(cx, cy);
        var innerRadius = radius * 0.90;

        var dialBrush = new RadialGradientBrush
        {
            Center = new Point(0.5, 0.42),
            GradientOrigin = new Point(0.5, 0.42),
            RadiusX = 0.65,
            RadiusY = 0.65,
        };
        var glowCenter = IsActive
            ? MixColor(faceColor, accentColor, 0.11)
            : MixColor(faceColor, Colors.White, 0.03);
        dialBrush.GradientStops.Add(new GradientStop(glowCenter, 0.0));
        dialBrush.GradientStops.Add(new GradientStop(WithAlpha(faceColor, 0.45), 1.0));
        dialBrush.Freeze();

        var rimPen = new Pen(FrozenBrush(WithAlpha(borderColor, 0.45)), 1.0);
        rimPen.Freeze();
        dc.DrawEllipse(dialBrush, rimPen, center, innerRadius, innerRadius);
    }

    private void DrawTrackAndRedline(DrawingContext dc, double cx, double cy, double radius, double thickness, Color trackColor, Color dangerColor)
    {
        var trackPen = new Pen(FrozenBrush(WithAlpha(trackColor, 0.62)), thickness)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
        };
        trackPen.Freeze();
        dc.DrawGeometry(null, trackPen, CreateArcGeometry(cx, cy, radius, StartAngleDeg, SweepAngleDeg));

        if (ShowRedlineZone)
        {
            var redStart = StartAngleDeg + (SweepAngleDeg * 0.75);
            var redSweep = SweepAngleDeg * 0.25;
            var redPen = new Pen(FrozenBrush(WithAlpha(dangerColor, 0.28)), thickness)
            {
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round,
            };
            redPen.Freeze();
            dc.DrawGeometry(null, redPen, CreateArcGeometry(cx, cy, radius, redStart, redSweep));
        }
    }

    private void DrawTickMarks(
        DrawingContext dc,
        double cx,
        double cy,
        double radius,
        double arcThickness,
        double visualNormalized,
        Color accentColor,
        Color dangerColor,
        Color secColor)
    {
        var outerR = radius - (arcThickness * 0.85);
        for (var i = 0; i <= TickIntervals; i++)
        {
            var fraction = i / (double)TickIntervals;
            var angleRad = (StartAngleDeg + (fraction * SweepAngleDeg)) * Math.PI / 180.0;
            var isMajor = i % 4 == 0;
            var tickLen = isMajor ? Math.Max(6.0, radius * 0.14) : Math.Max(3.5, radius * 0.08);
            var innerR = outerR - tickLen;

            var p1 = PolarPoint(cx, cy, innerR, angleRad);
            var p2 = PolarPoint(cx, cy, outerR, angleRad);

            var lit = visualNormalized > 0.005 && fraction <= visualNormalized + 0.015;
            Color tickColor;
            if (ShowRedlineZone && fraction >= 0.75)
            {
                tickColor = lit ? dangerColor : WithAlpha(dangerColor, 0.45);
            }
            else
            {
                tickColor = lit ? accentColor : WithAlpha(secColor, isMajor ? 0.58 : 0.34);
            }

            var pen = new Pen(FrozenBrush(tickColor), isMajor ? 1.7 : 1.0)
            {
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round,
            };
            pen.Freeze();
            dc.DrawLine(pen, p1, p2);
        }
    }

    private void DrawActiveArc(
        DrawingContext dc,
        double cx,
        double cy,
        double radius,
        double thickness,
        double visualNormalized,
        Color accentColor)
    {
        if (visualNormalized <= 0.005)
        {
            return;
        }

        var sweep = visualNormalized * SweepAngleDeg;
        var activeArc = CreateArcGeometry(cx, cy, radius, StartAngleDeg, sweep);

        var glowPen = new Pen(FrozenBrush(WithAlpha(accentColor, 0.22)), thickness * 1.95)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
        };
        glowPen.Freeze();
        dc.DrawGeometry(null, glowPen, activeArc);

        var mainPen = new Pen(FrozenBrush(accentColor), thickness)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
        };
        mainPen.Freeze();
        dc.DrawGeometry(null, mainPen, activeArc);

        if (IsActive && sweep > 20.0)
        {
            var cycle = (_animTime * 0.45 + PhaseOffset * 0.17) % 1.0;
            var pulseWidth = Math.Min(24.0, sweep * 0.45);
            var pulseStart = StartAngleDeg + (cycle * (sweep - pulseWidth));
            var pulseGeo = CreateArcGeometry(cx, cy, radius, pulseStart, pulseWidth);
            var pulsePen = new Pen(FrozenBrush(Color.FromArgb(0x8A, 0xFF, 0xFF, 0xFF)), Math.Max(2.0, thickness * 0.48))
            {
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round,
            };
            pulsePen.Freeze();
            dc.DrawGeometry(null, pulsePen, pulseGeo);
        }
    }

    private static void DrawNeedleAndHub(
        DrawingContext dc,
        double cx,
        double cy,
        double radius,
        double visualNormalized,
        Color accentColor,
        Color borderColor,
        Color faceColor)
    {
        var angleRad = (StartAngleDeg + (visualNormalized * SweepAngleDeg)) * Math.PI / 180.0;
        var tipLen = radius * 0.77;
        var tailLen = radius * 0.16;
        var baseHalfW = Math.Clamp(radius * 0.044, 2.0, 3.0);
        var tipHalfW = 0.7;

        var cos = Math.Cos(angleRad);
        var sin = Math.Sin(angleRad);
        var perpX = -sin;
        var perpY = cos;

        var needleGeo = new StreamGeometry();
        using (var ctx = needleGeo.Open())
        {
            var p0 = new Point(cx - (cos * tailLen) + (perpX * baseHalfW), cy - (sin * tailLen) + (perpY * baseHalfW));
            var p1 = new Point(cx + (cos * tipLen) + (perpX * tipHalfW), cy + (sin * tipLen) + (perpY * tipHalfW));
            var p2 = new Point(cx + (cos * tipLen) - (perpX * tipHalfW), cy + (sin * tipLen) - (perpY * tipHalfW));
            var p3 = new Point(cx - (cos * tailLen) - (perpX * baseHalfW), cy - (sin * tailLen) - (perpY * baseHalfW));

            ctx.BeginFigure(p0, isFilled: true, isClosed: true);
            ctx.LineTo(p1, isStroked: false, isSmoothJoin: false);
            ctx.LineTo(p2, isStroked: false, isSmoothJoin: false);
            ctx.LineTo(p3, isStroked: false, isSmoothJoin: false);
        }
        needleGeo.Freeze();

        var shadowGlow = new Pen(FrozenBrush(WithAlpha(accentColor, 0.28)), 2.5);
        shadowGlow.Freeze();
        dc.DrawGeometry(FrozenBrush(WithAlpha(accentColor, 0.92)), shadowGlow, needleGeo);

        var needleCore = FrozenBrush(MixColor(accentColor, Colors.White, 0.35));
        dc.DrawGeometry(needleCore, null, needleGeo);

        var center = new Point(cx, cy);
        var capOuterR = Math.Clamp(radius * 0.115, 5.5, 8.5);
        var capInnerR = capOuterR * 0.50;
        var capPen = new Pen(FrozenBrush(WithAlpha(borderColor, 0.85)), 1.2);
        capPen.Freeze();
        dc.DrawEllipse(FrozenBrush(MixColor(faceColor, Colors.White, 0.08)), capPen, center, capOuterR, capOuterR);
        dc.DrawEllipse(FrozenBrush(accentColor), null, center, capInnerR, capInnerR);
    }

    private void DrawScaleAndValueText(DrawingContext dc, double w, double h, double cx, double cy, double radius)
    {
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var secBrush = SecondaryTextBrush ?? Brushes.Gray;
        var mainBrush = TextBrush ?? Brushes.White;

        var zeroText = CreateFormattedText("0", LabelTypeface, 9.5, secBrush, dpi);
        var maxLabel = string.IsNullOrWhiteSpace(MaxScaleLabel) ? "100" : MaxScaleLabel;
        var maxText = CreateFormattedText(maxLabel, LabelTypeface, 9.5, secBrush, dpi);

        var scaleY = Math.Min(h - zeroText.Height - 1.0, cy + (radius * 0.56));
        var leftX = Math.Max(2.0, cx - (radius * 0.86) - (zeroText.Width * 0.3));
        var rightX = Math.Min(w - maxText.Width - 2.0, cx + (radius * 0.86) - (maxText.Width * 0.7));

        dc.DrawText(zeroText, new Point(leftX, scaleY));
        dc.DrawText(maxText, new Point(rightX, scaleY));

        var displayValue = string.IsNullOrWhiteSpace(ValueText) ? "—" : ValueText;
        var fontSize = displayValue.Length switch
        {
            <= 5 => 18.0,
            <= 8 => 15.5,
            _ => 13.5,
        };
        var valueFormatted = CreateFormattedText(displayValue, DisplayTypeface, fontSize, mainBrush, dpi);
        var valueX = Math.Clamp(cx - (valueFormatted.Width / 2.0), 2.0, Math.Max(2.0, w - valueFormatted.Width - 2.0));
        var valueY = Math.Min(h - valueFormatted.Height - 2.0, cy + (radius * 0.28));
        dc.DrawText(valueFormatted, new Point(valueX, valueY));
    }

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SpeedometerGaugeControl gauge && gauge.IsActive && !Equals(e.OldValue, e.NewValue))
        {
            gauge._pulseBoost = 0.024;
        }
    }

    private static StreamGeometry CreateArcGeometry(double cx, double cy, double radius, double startDeg, double sweepDeg)
    {
        var clampedSweep = Math.Clamp(sweepDeg, 0.0, 359.9);
        var startRad = startDeg * Math.PI / 180.0;
        var endRad = (startDeg + clampedSweep) * Math.PI / 180.0;

        var startPt = PolarPoint(cx, cy, radius, startRad);
        var endPt = PolarPoint(cx, cy, radius, endRad);
        var isLargeArc = clampedSweep > 180.0;

        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(startPt, isFilled: false, isClosed: false);
            ctx.ArcTo(endPt, new Size(radius, radius), 0.0, isLargeArc, SweepDirection.Clockwise, isStroked: true, isSmoothJoin: false);
        }

        geo.Freeze();
        return geo;
    }

    private static Point PolarPoint(double cx, double cy, double radius, double angleRad) =>
        new(cx + (radius * Math.Cos(angleRad)), cy + (radius * Math.Sin(angleRad)));

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

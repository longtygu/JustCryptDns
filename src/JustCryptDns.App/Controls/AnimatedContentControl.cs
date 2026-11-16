using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace JustCryptDns.App.Controls;

/// <summary>
/// ContentControl that plays a short, GPU-cheap fade/slide when its content changes (page navigation).
/// </summary>
public sealed class AnimatedContentControl : ContentControl
{
    /// <summary>Global multiplier for transition duration; 0 disables animation.</summary>
    public static double AnimationScale { get; set; } = 1.0;

    private readonly TranslateTransform _translate = new();

    public AnimatedContentControl()
    {
        RenderTransform = _translate;
        Focusable = false;
    }

    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);
        if (AnimationScale <= 0 || oldContent is null)
        {
            return;
        }

        var duration = TimeSpan.FromMilliseconds(200 * AnimationScale);
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, duration) { EasingFunction = ease });
        _translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(10, 0, duration) { EasingFunction = ease });
    }
}

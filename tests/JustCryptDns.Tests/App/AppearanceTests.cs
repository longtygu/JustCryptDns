using System.Windows;
using System.Windows.Media;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Services;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.App;

public sealed class AppearanceTests
{
    [Theory]
    [InlineData(0, TransparencyLevel.Opaque)]
    [InlineData(15, TransparencyLevel.Slight)]
    [InlineData(20, TransparencyLevel.Slight)]
    [InlineData(35, TransparencyLevel.Moderate)]
    [InlineData(40, TransparencyLevel.Moderate)]
    [InlineData(55, TransparencyLevel.Strong)]
    [InlineData(60, TransparencyLevel.Strong)]
    [InlineData(85, TransparencyLevel.High)]
    [InlineData(90, TransparencyLevel.High)]
    public void TransparencyLevels_MatchSpecification(int percent, TransparencyLevel expected)
    {
        Assert.Equal(expected, AppearanceMath.Level(percent));
    }

    [Fact]
    public void SurfaceAlphas_PreserveReadabilityEvenAtMaxTransparency()
    {
        var settings = new AppearanceSettings { TransparencyEnabled = true, Transparency = 90 };
        var fraction = AppearanceMath.RequestedFraction(settings);

        Assert.Equal(0.9, fraction, 3);
        var windowAlpha = AppearanceMath.WindowAlpha(fraction);
        var sidebarAlpha = AppearanceMath.SidebarAlpha(fraction);
        var cardAlpha = AppearanceMath.CardAlpha(fraction);

        // Hierarchy: cards are more opaque than sidebar, sidebar is more opaque than window background,
        // and cards retain >= 60% opacity at 90% transparency so text remains readable.
        Assert.True(windowAlpha > 0.30);
        Assert.True(sidebarAlpha > windowAlpha);
        Assert.True(cardAlpha > sidebarAlpha);
        Assert.True(cardAlpha >= 0.60);
    }

    [Fact]
    public void MasterSwitchOff_ForcesZeroTransparencyFraction()
    {
        var settings = new AppearanceSettings { TransparencyEnabled = false, Transparency = 75 };
        Assert.Equal(0, AppearanceMath.RequestedFraction(settings));
        var (kind, status) = AppearanceMath.Resolve(settings, new BackdropSupport(true, true, true));
        Assert.Equal(BackdropKind.None, kind);
        Assert.Equal(BackdropStatus.Disabled, status);
    }

    [Fact]
    public void BackdropResolution_FallsBackGracefullyAcrossSystems()
    {
        var win11 = new BackdropSupport(Mica: true, Acrylic: true, Blur: true);
        var win10 = new BackdropSupport(Mica: false, Acrylic: false, Blur: true);
        var none = new BackdropSupport(Mica: false, Acrylic: false, Blur: false);

        var autoSettings = new AppearanceSettings { Transparency = 40, Backdrop = BackdropPreference.Auto };
        Assert.Equal((BackdropKind.Acrylic, BackdropStatus.Active), AppearanceMath.Resolve(autoSettings, win11));
        Assert.Equal((BackdropKind.Blur, BackdropStatus.Active), AppearanceMath.Resolve(autoSettings, win10));
        Assert.Equal((BackdropKind.None, BackdropStatus.Unsupported), AppearanceMath.Resolve(autoSettings, none));

        var micaSettings = new AppearanceSettings { Transparency = 40, Backdrop = BackdropPreference.Mica };
        Assert.Equal((BackdropKind.Mica, BackdropStatus.Active), AppearanceMath.Resolve(micaSettings, win11));
        Assert.Equal((BackdropKind.Blur, BackdropStatus.Active), AppearanceMath.Resolve(micaSettings, win10));
    }

    [Theory]
    [InlineData("#4f8cff", "#4F8CFF")]
    [InlineData("10b981", "#10B981")]
    [InlineData("#abc", "#AABBCC")]
    [InlineData("  #F0A  ", "#FF00AA")]
    [InlineData("invalid", null)]
    [InlineData("#12345", null)]
    [InlineData("", null)]
    public void NormalizeRgb_HandlesAllInputForms(string input, string? expected)
    {
        Assert.Equal(expected, ColorText.NormalizeRgb(input));
    }

    [Fact]
    public void SystemAccent_ConvertsDwmAbgrValueToRgbHex()
    {
        // DWM AccentColor 0xFF_D7_78_00 => R=0x00, G=0x78, B=0xD7 => #0078D7
        Assert.Equal("#0078D7", SystemAccent.FromAbgr(0xFFD77800u));
    }

    [Fact]
    public void ComputeAccent_ChoosesReadableForegroundForAllPresets()
    {
        foreach (var hex in AppearanceViewModel.AccentPresets.Concat(["#FFFFFF", "#000000", "#EAB308"]))
        {
            var color = (Color)ColorConverter.ConvertFromString(hex);
            var palette = ThemeService.ComputeAccent(color, AppTheme.Dark);
            var accent = palette[0];
            var onAccent = palette[5];

            // OnAccent must always have strong contrast (>= 4.0) against the accent fill.
            Assert.True(ColorMath.ContrastRatio(accent, onAccent) >= 4.0, $"Low contrast for {hex}");
        }
    }

    [Fact]
    public void AppearanceViewModel_UpdatesSettingsIndependentlyAndResets()
    {
        var store = new MemoryStore();
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var appearance = new FakeAppearanceService();
        var nav = new NavigationService();
        var vm = new AppearanceViewModel(settings, appearance, nav);

        // Change theme and transparency independently
        vm.Theme = AppTheme.Light;
        vm.Transparency = 60;
        Assert.Equal(AppTheme.Light, settings.Current.Appearance.Theme);
        Assert.Equal(60, settings.Current.Appearance.Transparency);
        Assert.Equal(TransparencyLevel.Strong, vm.TransparencyLevel);

        // Switch theme to Custom without losing transparency
        vm.Theme = AppTheme.Custom;
        vm.CustomBaseTheme = AppTheme.Dark;
        vm.SelectTintCommand.Execute("#14B8A6");
        Assert.Equal(60, settings.Current.Appearance.Transparency);
        Assert.Equal("#14B8A6", settings.Current.Appearance.CustomTintColor);

        // Custom hex validation
        vm.AccentInput = "not-a-hex";
        vm.ApplyAccentInputCommand.Execute(null);
        Assert.True(vm.IsAccentInputInvalid);

        vm.AccentInput = "22c55e";
        vm.ApplyAccentInputCommand.Execute(null);
        Assert.False(vm.IsAccentInputInvalid);
        Assert.Equal("#22C55E", settings.Current.Appearance.AccentColor);

        // Reset restores defaults
        vm.ResetCommand.Execute(null);
        Assert.Equal(AppTheme.Dark, settings.Current.Appearance.Theme);
        Assert.Equal(0, settings.Current.Appearance.Transparency);
        Assert.Equal(AppearanceSettings.DefaultAccentColor, settings.Current.Appearance.AccentColor);
    }

    private sealed class MemoryStore : ISettingsStore
    {
        public SettingsLoadResult Load() => new(new AppSettings(), SettingsLoadOutcome.Defaults);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeAppearanceService : IAppearanceService
    {
        public BackdropSupport Support => new(Mica: false, Acrylic: false, Blur: true);

        public bool SupportsCornerStyle => false;

        public AppearanceState State { get; private set; } =
            new(BackdropKind.None, BackdropStatus.ZeroTransparency, 0, AppearanceSettings.DefaultAccentColor);

        public event EventHandler<AppearanceState>? Applied;

        public void AttachWindow(Window window)
        {
        }

        public void Apply(AppearanceSettings settings)
        {
            var (kind, status) = AppearanceMath.Resolve(settings, Support);
            State = new AppearanceState(kind, status, AppearanceMath.RequestedFraction(settings), settings.AccentColor);
            Applied?.Invoke(this, State);
        }
    }
}

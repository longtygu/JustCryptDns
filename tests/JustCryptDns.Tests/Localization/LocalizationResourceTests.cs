using System.Text.RegularExpressions;
using System.Xml.Linq;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Models;
using JustCryptDns.App.ViewModels;

namespace JustCryptDns.Tests.Localization;

public sealed partial class LocalizationResourceTests
{
    private static readonly string RepoRoot = FindRepoRoot();
    private static readonly string StringsDir = Path.Combine(RepoRoot, "src", "JustCryptDns.App", "Resources", "Strings");

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "JustCryptDns.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static Dictionary<string, string> Read(string file) =>
        XDocument.Load(Path.Combine(StringsDir, file)).Root!.Elements("data")
            .ToDictionary(e => e.Attribute("name")!.Value, e => e.Element("value")?.Value ?? string.Empty);

    [Fact]
    public void EnglishAndVietnamese_HaveIdenticalKeys()
    {
        var en = Read("Strings.resx");
        var vi = Read("Strings.vi.resx");

        Assert.Empty(en.Keys.Except(vi.Keys));
        Assert.Empty(vi.Keys.Except(en.Keys));
    }

    [Fact]
    public void NoValueIsEmpty()
    {
        foreach (var (key, value) in Read("Strings.resx").Concat(Read("Strings.vi.resx")))
        {
            Assert.False(string.IsNullOrWhiteSpace(value), $"Empty value for {key}");
        }
    }

    [Fact]
    public void FormatPlaceholders_MatchAcrossLanguages()
    {
        var en = Read("Strings.resx");
        var vi = Read("Strings.vi.resx");
        foreach (var key in en.Keys)
        {
            var a = Placeholder().Matches(en[key]).Select(m => m.Value).Order().ToList();
            var b = Placeholder().Matches(vi[key]).Select(m => m.Value).Order().ToList();
            Assert.True(a.SequenceEqual(b), $"Placeholder mismatch for {key}");
        }
    }

    [Fact]
    public void EveryKeyReferencedInXaml_Exists()
    {
        var keys = Read("Strings.resx").Keys.ToHashSet();
        var appDir = Path.Combine(RepoRoot, "src", "JustCryptDns.App");
        foreach (var file in Directory.EnumerateFiles(appDir, "*.xaml", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            foreach (Match m in LocUsage().Matches(text))
            {
                Assert.True(keys.Contains(m.Groups[1].Value), $"{Path.GetFileName(file)} references missing key {m.Groups[1].Value}");
            }

            foreach (Match m in FormatUsage().Matches(text))
            {
                Assert.True(keys.Contains(m.Groups[1].Value), $"{Path.GetFileName(file)} references missing format key {m.Groups[1].Value}");
            }
        }
    }

    [Fact]
    public void EnumAndCodeDerivedKeys_Exist()
    {
        var keys = Read("Strings.resx").Keys.ToHashSet();
        var expected = new List<string>();
        expected.AddRange(Enum.GetNames<LocalConnectivity>().Select(n => "Connectivity_" + n));
        expected.AddRange(Enum.GetNames<AdapterKind>().Select(n => "AdapterKind_" + n));
        expected.AddRange(Enum.GetNames<IpFamilyStatus>().Select(n => "IpStatus_" + n));
        expected.AddRange(Enum.GetNames<AppTheme>().Select(n => "Theme_" + n));
        expected.AddRange(Enum.GetNames<JustCryptDns.App.Services.BackdropKind>().Select(n => "BackdropKind_" + n));
        expected.AddRange(Enum.GetNames<JustCryptDns.App.Services.BackdropStatus>().Select(n => "BackdropStatus_" + n));
        expected.AddRange(Enum.GetNames<JustCryptDns.App.Services.TransparencyLevel>().Select(n => "TransparencyLevel_" + n));
        expected.AddRange(Enum.GetNames<CloseBehavior>().Select(n => "CloseBehavior_" + n));
        expected.AddRange(Enum.GetNames<JustCryptDns.Core.Ipc.ServiceConnectionState>().Select(n => "ServiceState_" + n));
        expected.AddRange(Enum.GetNames<JustCryptDns.Core.Ipc.DnsEngineState>().Select(n => "EngineState_" + n));
        expected.AddRange(Enum.GetNames<DnsFilteringCapability>().Select(n => "FilteringCap_" + n));
        expected.AddRange(Enum.GetNames<RoutingMatchKind>().Select(n => "RoutingMatch_" + n));
        expected.AddRange(Enum.GetNames<BlocklistCategory>().Select(n => "BlockCat_" + n));
        expected.AddRange(LanguageCodes.All.Select(c => "Lang_" + c));

        foreach (var page in new[] { "Diagnostics", "Monitor" })
        {
            var vm = new PlannedFeatureViewModel(page, 4, 4);
            expected.Add(vm.TitleKey);
            expected.Add(vm.SubtitleKey);
            expected.AddRange(vm.FeatureKeys);
        }

        foreach (var key in expected)
        {
            Assert.True(keys.Contains(key), $"Missing key {key}");
        }
    }

    [Fact]
    public void ResolveCulture_MapsLanguageCodes()
    {
        Assert.Equal("vi-VN", LocalizationManager.ResolveCulture(LanguageCodes.Vietnamese).Name);
        Assert.Equal("en-US", LocalizationManager.ResolveCulture(LanguageCodes.English).Name);
        Assert.Contains(LocalizationManager.ResolveCulture(LanguageCodes.System).Name, new[] { "vi-VN", "en-US" });
    }

    [Fact]
    public void Manager_SwitchesLanguageAtRuntime()
    {
        var manager = LocalizationManager.Instance;
        var changed = new List<string?>();
        manager.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        try
        {
            manager.SetLanguage(LanguageCodes.English);
            Assert.Equal("Settings", manager["Nav_Settings"]);
            changed.Clear();

            manager.SetLanguage(LanguageCodes.Vietnamese);
            Assert.Equal("Cài đặt", manager["Nav_Settings"]);
            Assert.Contains("Item[]", changed);
            Assert.Equal("[Missing_Key]", manager["Missing_Key"]);
        }
        finally
        {
            manager.SetLanguage(LanguageCodes.English);
        }
    }

    [GeneratedRegex(@"\{\d+\}")]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"\{l:Loc\s+([A-Za-z0-9_]+)\}")]
    private static partial Regex LocUsage();

    [GeneratedRegex(@"Converter=""\{StaticResource LocFormat\}""\s+ConverterParameter=""([A-Za-z0-9_]+)""")]
    private static partial Regex FormatUsage();
}

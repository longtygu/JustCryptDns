using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Configuration;

public sealed class SettingsServiceTests
{
    [Fact]
    public async Task Update_PersistsNormalizesAndRaisesChanged()
    {
        var store = new InMemoryStore();
        using var service = new SettingsService(store, NullLogger<SettingsService>.Instance);
        AppSettings? raised = null;
        service.Changed += (_, s) => raised = s;

        await service.UpdateAsync(s =>
        {
            s.Appearance.Theme = AppTheme.Light;
            s.Appearance.AccentColor = "not-a-color";
        });

        Assert.Equal(1, store.SaveCount);
        Assert.NotNull(raised);
        Assert.Equal(AppTheme.Light, service.Current.Appearance.Theme);
        Assert.Equal(AppearanceSettings.DefaultAccentColor, service.Current.Appearance.AccentColor);
    }

    [Fact]
    public async Task Update_WhenSaveFails_LeavesCurrentUnchanged()
    {
        var store = new InMemoryStore { FailSaves = true };
        using var service = new SettingsService(store, NullLogger<SettingsService>.Instance);

        await Assert.ThrowsAsync<IOException>(() => service.UpdateAsync(s => s.Appearance.Theme = AppTheme.Light));

        Assert.Equal(AppTheme.Dark, service.Current.Appearance.Theme);
    }

    [Fact]
    public async Task Update_WithNewerSchema_DoesNotOverwriteFile()
    {
        var store = new InMemoryStore { Outcome = SettingsLoadOutcome.NewerSchemaReadOnly };
        using var service = new SettingsService(store, NullLogger<SettingsService>.Instance);

        await service.UpdateAsync(s => s.Appearance.Theme = AppTheme.Light);

        Assert.Equal(0, store.SaveCount);
        Assert.Equal(AppTheme.Light, service.Current.Appearance.Theme);
    }

    [Fact]
    public async Task UpdateDeferred_UpdatesCurrentImmediatelyAndFlushesOnce()
    {
        var store = new InMemoryStore();
        using var service = new SettingsService(store, NullLogger<SettingsService>.Instance);

        service.UpdateDeferred(s => s.Appearance.Transparency = 20);
        service.UpdateDeferred(s => s.Appearance.Transparency = 45);
        service.UpdateDeferred(s => s.Appearance.Transparency = 60);

        Assert.Equal(60, service.Current.Appearance.Transparency);
        Assert.Equal(0, store.SaveCount);

        await service.FlushAsync();

        Assert.Equal(1, store.SaveCount);
    }

    private sealed class InMemoryStore : ISettingsStore
    {
        public int SaveCount { get; private set; }

        public bool FailSaves { get; init; }

        public SettingsLoadOutcome Outcome { get; init; } = SettingsLoadOutcome.Defaults;

        public SettingsLoadResult Load() => new(new AppSettings(), Outcome);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            if (FailSaves)
            {
                throw new IOException("disk full");
            }

            SaveCount++;
            return Task.CompletedTask;
        }
    }
}

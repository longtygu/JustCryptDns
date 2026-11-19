using System.Buffers.Binary;
using System.Windows.Controls;
using JustCryptDns.App;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Infrastructure.Ipc;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

namespace JustCryptDns.Tests.Background;

public sealed class BackgroundOperationTests : IDisposable
{
    private const string TestRegistryRoot = @"Software\JustCryptDns-Tests";
    private readonly string _testRunSubKey = $@"{TestRegistryRoot}\Run-{Guid.NewGuid():N}";

    public void Dispose()
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(TestRegistryRoot, throwOnMissingSubKey: false);
        }
        catch (Exception)
        {
            // Ignore cleanup errors.
        }
    }

    [Fact]
    public async Task NamedPipeIpc_RoundTripsStatusAndCommandsAndDetectsShutdown()
    {
        var pipeName = $"JustCryptDns.Test.{Guid.NewGuid():N}";
        var tempRoot = Path.Combine(Path.GetTempPath(), "jcd-ipc-test", Guid.NewGuid().ToString("N"));
        var paths = new AppPaths(tempRoot);
        paths.EnsureCreated();
        try
        {
            var freePort = JustCryptDns.DNS.Proxy.PortConflictDetector.GetEphemeralPort(System.Net.IPAddress.Loopback);
            var store = new MemorySettingsStore(new AppSettings
            {
                General = { AutoStartDnsEngine = false, EnableGamingModeOnStartup = false },
                Dns = { ListenPort = freePort },
            });
            using var settingsService = new JustCryptDns.Core.Services.SettingsService(store, NullLogger<JustCryptDns.Core.Services.SettingsService>.Instance);
            using var netInfo = new JustCryptDns.Network.Monitoring.NetworkInfoService(NullLogger<JustCryptDns.Network.Monitoring.NetworkInfoService>.Instance);
            var winDns = new WindowsNetworkDnsService(paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance);
            await using var dnsCrypt = new JustCryptDns.DNS.DnsCrypt.DnsCryptProxyManager(paths, NullLogger<JustCryptDns.DNS.DnsCrypt.DnsCryptProxyManager>.Instance);
            await using var dnsEngine = new JustCryptDns.DNS.Proxy.DnsEngineService(settingsService, dnsCrypt, winDns, NullLogger<JustCryptDns.DNS.Proxy.DnsEngineService>.Instance);
            var stateManager = new ServiceStateManager(settingsService, dnsEngine, winDns, NullLogger<ServiceStateManager>.Instance);
            await stateManager.InitializeFromSettingsAsync();

            var server = new NamedPipeIpcServer(stateManager, NullLogger<NamedPipeIpcServer>.Instance, pipeName);
            var client = new NamedPipeServiceClient(NullLogger<NamedPipeServiceClient>.Instance, pipeName);

            server.Start();
            try
            {
                var status = await client.RefreshStatusAsync();
                Assert.NotNull(status);
                Assert.Equal(ServiceConnectionState.Connected, client.ConnectionState);
                Assert.Equal(DnsEngineState.Stopped, status!.EngineState);
                Assert.True(status.IsEngineImplemented);
                Assert.False(status.IsGamingModeEnabled);

                var gamingResponse = await client.SendAsync(new IpcRequest(IpcRequestKind.SetGamingMode, BoolValue: true));
                Assert.NotNull(gamingResponse);
                Assert.True(gamingResponse!.Success);
                Assert.True(gamingResponse.Status.IsGamingModeEnabled);

                var engineStart = await client.SendAsync(new IpcRequest(IpcRequestKind.SetEngineEnabled, BoolValue: true));
                Assert.NotNull(engineStart);
                Assert.True(engineStart!.Success);
                Assert.Equal(DnsEngineState.Running, engineStart.Status.EngineState);

                var engineStop = await client.SendAsync(new IpcRequest(IpcRequestKind.SetEngineEnabled, BoolValue: false));
                Assert.NotNull(engineStop);
                Assert.True(engineStop!.Success);
                Assert.Equal(DnsEngineState.Stopped, engineStop.Status.EngineState);

                var badVersionResponse = await client.SendAsync(new IpcRequest(IpcRequestKind.GetStatus, ProtocolVersion: 99));
                Assert.NotNull(badVersionResponse);
                Assert.False(badVersionResponse!.Success);
                Assert.Equal("ProtocolMismatch", badVersionResponse.ErrorCode);
            }
            finally
            {
                await server.DisposeAsync();
            }

            // After server stops, client reports ServiceNotRunning.
            var afterStop = await client.RefreshStatusAsync();
            Assert.Null(afterStop);
            Assert.Equal(ServiceConnectionState.ServiceNotRunning, client.ConnectionState);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task IpcFraming_RejectsInvalidAndTruncatedFrames()
    {
        using var oversized = new MemoryStream();
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, IpcConstants.MaxMessageBytes + 1);
        oversized.Write(header);
        oversized.Position = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => IpcFraming.ReadMessageAsync<IpcRequest>(oversized));

        using var truncated = new MemoryStream([1, 2]);
        await Assert.ThrowsAsync<EndOfStreamException>(() => IpcFraming.ReadMessageAsync<IpcRequest>(truncated));
    }

    [Fact]
    public void RegistryStartupService_IsIdempotentAndRemovesCleanly()
    {
        var exePath = @"C:\Program Files\JustCryptDns\JustCryptDns.exe";
        var service = new RegistryStartupService(
            NullLogger<RegistryStartupService>.Instance,
            runSubKeyOverride: _testRunSubKey,
            executablePathOverride: exePath);

        Assert.False(service.IsRegistered());

        service.SetRegistration(enabled: true, startMinimized: false);
        Assert.True(service.IsRegistered());

        using (var key = Registry.CurrentUser.OpenSubKey(_testRunSubKey)!)
        {
            Assert.Single(key.GetValueNames());
            Assert.Equal($"\"{exePath}\" --autostart", key.GetValue(RegistryStartupService.ValueName));
        }

        // Calling again with startMinimized=true updates in place without creating duplicate values.
        service.SetRegistration(enabled: true, startMinimized: true);
        using (var key = Registry.CurrentUser.OpenSubKey(_testRunSubKey)!)
        {
            Assert.Single(key.GetValueNames());
            Assert.Equal($"\"{exePath}\" --autostart --minimized", key.GetValue(RegistryStartupService.ValueName));
        }

        service.SetRegistration(enabled: false, startMinimized: false);
        Assert.False(service.IsRegistered());
    }

    [Fact]
    public void ShouldStartMinimized_RespectsArgsAndSettings()
    {
        var normal = new GeneralSettings { StartMinimized = false };
        var minSetting = new GeneralSettings { StartMinimized = true };

        Assert.False(JustCryptDns.App.App.ShouldStartMinimized([], normal));
        Assert.True(JustCryptDns.App.App.ShouldStartMinimized(["--minimized"], normal));
        Assert.True(JustCryptDns.App.App.ShouldStartMinimized([], minSetting));
        Assert.False(JustCryptDns.App.App.ShouldStartMinimized(["--minimized", "--show"], minSetting));
    }

    [Fact]
    public void TrayIconService_BuildsContextMenuWithAllSevenActions()
    {
        Exception? error = null;
        var itemCount = 0;

        var thread = new Thread(() =>
        {
            try
            {
                var client = new NamedPipeServiceClient(NullLogger<NamedPipeServiceClient>.Instance, "NonExistentPipe");
                var nav = new NavigationService();
                using var tray = new TrayIconService(client, nav, NullLogger<TrayIconService>.Instance);
                var menu = tray.BuildContextMenu();
                itemCount = menu.Items.OfType<MenuItem>().Count();
            }
            catch (Exception ex)
            {
                error = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(error);
        Assert.Equal(7, itemCount);
    }

    private sealed class MemorySettingsStore(AppSettings settings) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(settings.Clone(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings value, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Offline Authenticode signature verifier (Win32 <c>wintrust.dll</c>), risky-directory detector,
/// and system binary masquerading analyzer. Results are cached per executable path &amp; timestamp.
/// </summary>
public sealed class ProcessTrustInspector : IProcessTrustInspector
{
    private const int MaxCacheEntries = 1024;
    private const long TrustCacheMetadataTtlMs = 30_000;
    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private static readonly HashSet<string> CoreWindowsBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe",
        "csrss.exe",
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
        "smss.exe",
        "explorer.exe",
        "conhost.exe",
        "taskhostw.exe",
        "dllhost.exe",
        "spoolsv.exe",
        "wininit.exe",
    };

    private static readonly string WindowsDirectory = NormalizeDir(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private static readonly string System32Directory = NormalizeDir(Environment.GetFolderPath(Environment.SpecialFolder.System));
    private static readonly string SysWow64Directory = NormalizeDir(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86));

    private readonly ConcurrentDictionary<string, (long LastWriteUtcTicks, long VerifiedAtTick, ProcessTrustInfo Info)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public ProcessTrustInfo Inspect(string? executablePath, string? processName = null)
    {
        if (string.IsNullOrWhiteSpace(executablePath)
            && (string.Equals(processName, "System", StringComparison.OrdinalIgnoreCase)
                || string.Equals(processName, "System Idle", StringComparison.OrdinalIgnoreCase)))
        {
            return new ProcessTrustInfo(processName ?? "System", ProcessTrustLevel.TrustedSystem, "Microsoft Windows", false, false, null);
        }

        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return new ProcessTrustInfo(processName ?? string.Empty, ProcessTrustLevel.Unknown, null, false, false, "Process path inaccessible without elevation.");
        }

        string normalized;
        try
        {
            normalized = Path.GetFullPath(executablePath.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new ProcessTrustInfo(executablePath, ProcessTrustLevel.Unknown, null, false, false, null);
        }

        var nowTick = Environment.TickCount64;
        if (_cache.TryGetValue(normalized, out var cached) && nowTick - cached.VerifiedAtTick < TrustCacheMetadataTtlMs)
        {
            return cached.Info;
        }

        long stampTicks = 0;
        if (File.Exists(normalized))
        {
            try
            {
                stampTicks = File.GetLastWriteTimeUtc(normalized).Ticks;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                stampTicks = 0;
            }
        }

        if (cached.Info is not null && cached.LastWriteUtcTicks == stampTicks)
        {
            _cache[normalized] = (stampTicks, nowTick, cached.Info);
            return cached.Info;
        }

        var evaluated = EvaluateCore(normalized);
        if (_cache.Count >= MaxCacheEntries)
        {
            var victimCount = MaxCacheEntries / 5;
            foreach (var key in _cache
                .OrderBy(kvp => kvp.Value.VerifiedAtTick)
                .Take(victimCount)
                .Select(kvp => kvp.Key)
                .ToList())
            {
                _cache.TryRemove(key, out _);
            }
        }

        _cache[normalized] = (stampTicks, nowTick, evaluated);
        return evaluated;
    }

    private static ProcessTrustInfo EvaluateCore(string fullPath)
    {
        var fileName = Path.GetFileName(fullPath);
        var isRiskyPath = IsRiskyExecutionPath(fullPath);
        var inWindowsRoot = !isRiskyPath && IsUnderDirectory(fullPath, WindowsDirectory);
        var inSystemFolder = !isRiskyPath
            && (IsUnderDirectory(fullPath, System32Directory)
                || IsUnderDirectory(fullPath, SysWow64Directory)
                || inWindowsRoot);

        var isMasquerading = CoreWindowsBinaries.Contains(fileName) && !inSystemFolder;

        if (isMasquerading)
        {
            return new ProcessTrustInfo(
                fullPath,
                ProcessTrustLevel.Suspicious,
                null,
                true,
                true,
                $"Executable '{fileName}' is running outside Windows system directories ({Path.GetDirectoryName(fullPath)}).");
        }

        var isSigned = OperatingSystem.IsWindows()
            && File.Exists(fullPath)
            && (VerifyAuthenticodeOffline(fullPath) || VerifyCatalogSignatureOffline(fullPath));
        var publisher = isSigned ? TryExtractPublisher(fullPath) : null;

        if (isSigned)
        {
            if (isRiskyPath)
            {
                return new ProcessTrustInfo(
                    fullPath,
                    ProcessTrustLevel.Signed,
                    publisher,
                    true,
                    false,
                    "Signed executable launched from user Temp/Downloads folder.");
            }

            if (inWindowsRoot)
            {
                return new ProcessTrustInfo(
                    fullPath,
                    ProcessTrustLevel.TrustedSystem,
                    publisher ?? "Microsoft Windows",
                    false,
                    false,
                    null);
            }

            return new ProcessTrustInfo(
                fullPath,
                ProcessTrustLevel.Signed,
                publisher,
                false,
                false,
                null);
        }

        if (isRiskyPath)
        {
            return new ProcessTrustInfo(
                fullPath,
                ProcessTrustLevel.Suspicious,
                null,
                true,
                false,
                $"Unsigned executable running from high-risk path ({Path.GetDirectoryName(fullPath)}).");
        }

        return new ProcessTrustInfo(
            fullPath,
            ProcessTrustLevel.Unsigned,
            null,
            false,
            false,
            "No valid Authenticode digital signature.");
    }

    internal static bool IsRiskyExecutionPath(string fullPath)
    {
        var normalized = fullPath.Replace('/', '\\');
        return normalized.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase);
    }

    private static string? TryExtractPublisher(string fullPath)
    {
        try
        {
            using var rawCert = X509Certificate.CreateFromSignedFile(fullPath);
            using var cert = new X509Certificate2(rawCert);
            var name = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(name) ? null : name.Trim();
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool VerifyAuthenticodeOffline(string fullPath)
    {
        const uint wtdUiNone = 2;
        const uint wtdRevokeNone = 0;
        const uint wtdChoiceFile = 1;
        const uint wtdStateActionVerify = 1;
        const uint wtdStateActionClose = 2;
        const uint wtdCacheOnlyUrlRetrieval = 0x00000004;
        const uint wtdRevocationCheckNone = 0x00000010;

        nint pathPtr = nint.Zero;
        nint fileInfoPtr = nint.Zero;
        var wtd = new NativeMethods.WinTrustData();
        var actionGuid = ActionGenericVerifyV2;

        try
        {
            pathPtr = Marshal.StringToHGlobalUni(fullPath);
            var fileInfo = new NativeMethods.WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WinTrustFileInfo>(),
                pcwszFilePath = pathPtr,
                hFile = nint.Zero,
                pgKnownSubject = nint.Zero,
            };

            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            wtd.cbStruct = (uint)Marshal.SizeOf<NativeMethods.WinTrustData>();
            wtd.dwUIChoice = wtdUiNone;
            wtd.fdwRevocationChecks = wtdRevokeNone;
            wtd.dwUnionChoice = wtdChoiceFile;
            wtd.pFile = fileInfoPtr;
            wtd.dwStateAction = wtdStateActionVerify;
            wtd.dwProvFlags = wtdCacheOnlyUrlRetrieval | wtdRevocationCheckNone;

            var status = NativeMethods.WinVerifyTrust(nint.Zero, ref actionGuid, ref wtd);
            return status == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or AccessViolationException)
        {
            return false;
        }
        finally
        {
            if (wtd.hWVTStateData != nint.Zero)
            {
                wtd.dwStateAction = wtdStateActionClose;
                _ = NativeMethods.WinVerifyTrust(nint.Zero, ref actionGuid, ref wtd);
            }

            if (fileInfoPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }

            if (pathPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(pathPtr);
            }
        }
    }

    private static bool VerifyCatalogSignatureOffline(string fullPath)
    {
        try
        {
            using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var fileHandle = stream.SafeFileHandle.DangerousGetHandle();
            if (fileHandle == nint.Zero)
            {
                return false;
            }

            // Try SHA256 catalog first (Windows 10/11 default), then legacy default (SHA1).
            return TryMatchCatalogWithAlgorithm(fileHandle, "SHA256")
                || TryMatchCatalogWithAlgorithm(fileHandle, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    private static bool TryMatchCatalogWithAlgorithm(nint fileHandle, string? hashAlgorithm)
    {
        var catAdmin = nint.Zero;
        try
        {
            var acquired = hashAlgorithm is not null
                ? NativeMethods.CryptCATAdminAcquireContext2(out catAdmin, nint.Zero, hashAlgorithm, nint.Zero, 0)
                : NativeMethods.CryptCATAdminAcquireContext(out catAdmin, nint.Zero, 0);
            if (!acquired || catAdmin == nint.Zero)
            {
                return false;
            }

            uint hashSize = 0;
            _ = hashAlgorithm is not null
                ? NativeMethods.CryptCATAdminCalcHashFromFileHandle2(catAdmin, fileHandle, ref hashSize, null, 0)
                : NativeMethods.CryptCATAdminCalcHashFromFileHandle(fileHandle, ref hashSize, null, 0);
            if (hashSize == 0 || hashSize > 128)
            {
                return false;
            }

            var hash = new byte[hashSize];
            var hashed = hashAlgorithm is not null
                ? NativeMethods.CryptCATAdminCalcHashFromFileHandle2(catAdmin, fileHandle, ref hashSize, hash, 0)
                : NativeMethods.CryptCATAdminCalcHashFromFileHandle(fileHandle, ref hashSize, hash, 0);
            if (!hashed)
            {
                return false;
            }

            var catInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashSize, 0, nint.Zero);
            if (catInfo == nint.Zero)
            {
                return false;
            }

            try
            {
                var info = new NativeMethods.CatalogInfo
                {
                    cbStruct = (uint)Marshal.SizeOf<NativeMethods.CatalogInfo>(),
                    wszCatalogFile = string.Empty,
                };
                if (!NativeMethods.CryptCATCatalogInfoFromContext(catInfo, ref info, 0)
                    || string.IsNullOrWhiteSpace(info.wszCatalogFile))
                {
                    return false;
                }

                return VerifyAuthenticodeOffline(info.wszCatalogFile);
            }
            finally
            {
                _ = NativeMethods.CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            }
        }
        finally
        {
            if (catAdmin != nint.Zero)
            {
                _ = NativeMethods.CryptCATAdminReleaseContext(catAdmin, 0);
            }
        }
    }

    private static string NormalizeDir(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
    }

    private static bool IsUnderDirectory(string fullPath, string normalizedDirWithSlash) =>
        !string.IsNullOrEmpty(normalizedDirWithSlash)
        && fullPath.StartsWith(normalizedDirWithSlash, StringComparison.OrdinalIgnoreCase);

    private static class NativeMethods
    {
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int WinVerifyTrust(nint hwnd, ref Guid pgActionId, ref WinTrustData pWvtData);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminAcquireContext(out nint phCatAdmin, nint pgSubsystem, uint dwFlags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminAcquireContext2(
            out nint phCatAdmin,
            nint pgSubsystem,
            string? pwszHashAlgorithm,
            nint pStrongHashPolicy,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminReleaseContext(nint hCatAdmin, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminCalcHashFromFileHandle(
            nint hFile,
            ref uint pcbHash,
            [Out] byte[]? pbHash,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminCalcHashFromFileHandle2(
            nint hCatAdmin,
            nint hFile,
            ref uint pcbHash,
            [Out] byte[]? pbHash,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern nint CryptCATAdminEnumCatalogFromHash(
            nint hCatAdmin,
            byte[] pbHash,
            uint cbHash,
            uint dwFlags,
            nint phPrevCatInfo);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATCatalogInfoFromContext(
            nint hCatInfo,
            ref CatalogInfo psCatInfo,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCATAdminReleaseCatalogContext(
            nint hCatAdmin,
            nint hCatInfo,
            uint dwFlags);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CatalogInfo
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WinTrustFileInfo
        {
            public uint cbStruct;
            public nint pcwszFilePath;
            public nint hFile;
            public nint pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WinTrustData
        {
            public uint cbStruct;
            public nint pPolicyCallbackData;
            public nint pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public nint pFile;
            public uint dwStateAction;
            public nint hWVTStateData;
            public nint pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public nint pSignatureSettings;
        }
    }
}

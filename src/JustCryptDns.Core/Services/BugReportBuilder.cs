using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Services;

/// <summary>
/// Formats privacy-sanitized bug reports for GitHub Issues and Facebook messages to the author.
/// </summary>
public static partial class BugReportBuilder
{
    public const string AuthorName = "Longtygu";
    public const string AuthorTagline = "From Longtygu with luv <3";
    public const string GitHubRepoUrl = "https://github.com/longtygu/JustCryptDns";
    public const string GitHubNewIssueUrl = "https://github.com/longtygu/JustCryptDns/issues/new";
    public const string AuthorFacebookUrl = "https://www.facebook.com/longtygu/";

    /// <summary>
    /// Kept conservative (&lt;= 1800 chars) so GitHub's /login?return_to=&lt;encoded&gt; redirect for non-owners
    /// or signed-out browsers never overflows server/proxy URL length limits.
    /// </summary>
    public const int MaxGitHubIssueUrlLength = 1800;

    public static string SanitizeLogLine(string? line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return string.Empty;
        }

        return UserProfilePathRegex().Replace(line, "${prefix}<user>");
    }

    public static string BuildGitHubMarkdown(BugReportDraft draft, BugDiagnosticsSnapshot? diagnostics)
    {
        ArgumentNullException.ThrowIfNull(draft);
        return BuildGitHubMarkdownCore(draft, diagnostics, includeLogs: true, compactForUrl: false);
    }

    public static string BuildGitHubIssueUrl(BugReportDraft draft, BugDiagnosticsSnapshot? diagnostics)
    {
        ArgumentNullException.ThrowIfNull(draft);

        var rawTitle = string.IsNullOrWhiteSpace(draft.Title)
            ? $"[{FormatCategory(draft.Category)}] Bug report"
            : $"[{FormatCategory(draft.Category)}] {draft.Title.Trim()}";
        var effectiveTitle = rawTitle.Length > 120 ? rawTitle[..120] : rawTitle;

        var body = BuildGitHubMarkdown(draft, diagnostics);
        var url = ComposeIssueUrl(effectiveTitle, body);
        if (url.Length <= MaxGitHubIssueUrlLength)
        {
            return url;
        }

        // Drop verbose logs for URL safety; full markdown + logs are copied to clipboard by the caller.
        body = BuildGitHubMarkdownCore(draft, diagnostics, includeLogs: false, compactForUrl: true)
            + "\n> *Full report & logs copied to clipboard — press Ctrl+V here if truncated.*";
        url = ComposeIssueUrl(effectiveTitle, body);
        if (url.Length <= MaxGitHubIssueUrlLength)
        {
            return url;
        }

        var low = 0;
        var high = body.Length;
        while (low < high)
        {
            var mid = (low + high + 1) / 2;
            var candidateBody = body[..mid] + "\n...(copied to clipboard)";
            if (ComposeIssueUrl(effectiveTitle, candidateBody).Length <= MaxGitHubIssueUrlLength)
            {
                low = mid;
            }
            else
            {
                high = mid - 1;
            }
        }

        var truncatedBody = low > 0
            ? body[..low] + "\n...(copied to clipboard)"
            : "Full report copied to clipboard (press Ctrl+V).";
        return ComposeIssueUrl(effectiveTitle, truncatedBody);
    }

    public static string BuildFacebookMessage(BugReportDraft draft, BugDiagnosticsSnapshot? diagnostics)
    {
        ArgumentNullException.ThrowIfNull(draft);

        var sb = new StringBuilder();
        var version = diagnostics?.AppVersion ?? "?";
        var title = string.IsNullOrWhiteSpace(draft.Title) ? "Bug Report" : draft.Title.Trim();
        sb.AppendLine(CultureInfo.InvariantCulture, $"[JustCryptDns v{version} - {FormatCategory(draft.Category)}] {title}");
        sb.AppendLine();
        sb.AppendLine(string.IsNullOrWhiteSpace(draft.Description) ? "(No detailed description provided)" : draft.Description.Trim());

        var attachments = GetSafeAttachmentNames(draft.AttachedImagePaths);
        if (attachments.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"Attached screenshots ({attachments.Count} — paste or drop in Messenger):");
            foreach (var name in attachments)
            {
                sb.AppendLine("- " + name);
            }
        }

        if (draft.IncludeDiagnostics && diagnostics is not null)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"OS: {diagnostics.OsVersion}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"DNS Engine: {diagnostics.DnsEngineState} (Resolver: {diagnostics.ActiveResolver})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"DPI Bypass: {diagnostics.BypassState} ({diagnostics.BypassCoverage})");
            sb.AppendLine(CultureInfo.InvariantCulture, $"Adapter: {diagnostics.PrimaryAdapter}");

            if (diagnostics.RecentLogLines.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Recent warnings/errors:");
                var tail = diagnostics.RecentLogLines.TakeLast(5);
                foreach (var line in tail)
                {
                    sb.AppendLine("- " + SanitizeLogLine(line));
                }
            }
        }

        return sb.ToString().TrimEnd();
    }

    private static string BuildGitHubMarkdownCore(
        BugReportDraft draft,
        BugDiagnosticsSnapshot? diagnostics,
        bool includeLogs,
        bool compactForUrl)
    {
        var sb = new StringBuilder();
        sb.AppendLine("### Category");
        sb.AppendLine(FormatCategory(draft.Category));
        sb.AppendLine();
        sb.AppendLine("### Description");
        sb.AppendLine(string.IsNullOrWhiteSpace(draft.Description) ? "_Describe what happened and how to reproduce it._" : draft.Description.Trim());

        var attachments = GetSafeAttachmentNames(draft.AttachedImagePaths);
        if (attachments.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("### Attached Screenshots");
            foreach (var name in attachments)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"- `{name}`");
            }

            if (!compactForUrl)
            {
                sb.AppendLine("_(Paste `Ctrl+V` or drag & drop the attached screenshot files above into this GitHub issue box.)_");
            }
        }

        if (draft.IncludeDiagnostics && diagnostics is not null)
        {
            sb.AppendLine();
            sb.AppendLine("### Environment");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **App Version:** {diagnostics.AppVersion}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **OS:** {diagnostics.OsVersion}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **DNS Engine:** {diagnostics.DnsEngineState} (`{diagnostics.ActiveResolver}`)");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **DPI Bypass:** {diagnostics.BypassState} (`{diagnostics.BypassCoverage}`)");
            if (!compactForUrl)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"- **Primary Adapter:** {diagnostics.PrimaryAdapter}");
            }

            if (includeLogs && diagnostics.RecentLogLines.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("<details>");
                sb.AppendLine(CultureInfo.InvariantCulture, $"<summary>Recent warnings / errors ({diagnostics.RecentLogLines.Count} lines, sanitized)</summary>");
                sb.AppendLine();
                sb.AppendLine("```text");
                foreach (var line in diagnostics.RecentLogLines)
                {
                    sb.AppendLine(SanitizeLogLine(line));
                }

                sb.AppendLine("```");
                sb.AppendLine("</details>");
            }
        }

        return sb.ToString().TrimEnd() + Environment.NewLine;
    }

    private static List<string> GetSafeAttachmentNames(IReadOnlyList<string>? paths)
    {
        if (paths is null || paths.Count == 0)
        {
            return [];
        }

        return paths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => SanitizeLogLine(Path.GetFileName(p.Trim())))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    // Never include `labels=` query parameter because non-owner GitHub users lack repo triage permissions.
    private static string ComposeIssueUrl(string title, string body) =>
        $"{GitHubNewIssueUrl}?title={Uri.EscapeDataString(title)}&body={Uri.EscapeDataString(body)}";

    private static string FormatCategory(BugReportCategory category) => category switch
    {
        BugReportCategory.DnsEngine => "DNS Engine",
        BugReportCategory.DpiBypass => "DPI Bypass & Split-Tunnel",
        BugReportCategory.Gaming => "Gaming Mode",
        BugReportCategory.UiAppearance => "UI / Appearance",
        BugReportCategory.AutoUpdate => "Auto-Update",
        _ => "Other",
    };

    [GeneratedRegex(@"(?<prefix>[A-Za-z]:\\Users\\)[^\\/\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserProfilePathRegex();
}

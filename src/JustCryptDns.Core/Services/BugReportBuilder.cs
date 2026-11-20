using System.Globalization;
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

    private const int MaxGitHubIssueUrlLength = 5500;

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
        return BuildGitHubMarkdownCore(draft, diagnostics, includeLogs: true);
    }

    public static string BuildGitHubIssueUrl(BugReportDraft draft, BugDiagnosticsSnapshot? diagnostics)
    {
        ArgumentNullException.ThrowIfNull(draft);

        var effectiveTitle = string.IsNullOrWhiteSpace(draft.Title)
            ? $"[{FormatCategory(draft.Category)}] Bug report"
            : $"[{FormatCategory(draft.Category)}] {draft.Title.Trim()}";

        var body = BuildGitHubMarkdown(draft, diagnostics);
        var url = ComposeIssueUrl(effectiveTitle, body);
        if (url.Length <= MaxGitHubIssueUrlLength)
        {
            return url;
        }

        // First drop verbose log lines so browser URL limits are respected; full body is copied to clipboard.
        body = BuildGitHubMarkdownCore(draft, diagnostics, includeLogs: false)
            + "\n> *Note: Recent logs were omitted from the URL to keep it under browser limits (full report copied to clipboard — paste here if needed).*";
        url = ComposeIssueUrl(effectiveTitle, body);
        if (url.Length <= MaxGitHubIssueUrlLength)
        {
            return url;
        }

        // Binary shrink the body until encoded URL fits safely.
        var low = 0;
        var high = body.Length;
        while (low < high)
        {
            var mid = (low + high + 1) / 2;
            var candidateBody = body[..mid] + "\n...(truncated — full report copied to clipboard)";
            if (ComposeIssueUrl(effectiveTitle, candidateBody).Length <= MaxGitHubIssueUrlLength)
            {
                low = mid;
            }
            else
            {
                high = mid - 1;
            }
        }

        var truncatedBody = body[..low] + "\n...(truncated — full report copied to clipboard)";
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

    private static string BuildGitHubMarkdownCore(BugReportDraft draft, BugDiagnosticsSnapshot? diagnostics, bool includeLogs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("### Category");
        sb.AppendLine(FormatCategory(draft.Category));
        sb.AppendLine();
        sb.AppendLine("### Description");
        sb.AppendLine(string.IsNullOrWhiteSpace(draft.Description) ? "_Describe what happened and how to reproduce it._" : draft.Description.Trim());

        if (draft.IncludeDiagnostics && diagnostics is not null)
        {
            sb.AppendLine();
            sb.AppendLine("### Environment");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **App Version:** {diagnostics.AppVersion}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **OS:** {diagnostics.OsVersion}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **DNS Engine:** {diagnostics.DnsEngineState} (`{diagnostics.ActiveResolver}`)");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **DPI Bypass:** {diagnostics.BypassState} (`{diagnostics.BypassCoverage}`)");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- **Primary Adapter:** {diagnostics.PrimaryAdapter}");

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

    private static string ComposeIssueUrl(string title, string body) =>
        $"{GitHubNewIssueUrl}?labels=bug&title={Uri.EscapeDataString(title)}&body={Uri.EscapeDataString(body)}";

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

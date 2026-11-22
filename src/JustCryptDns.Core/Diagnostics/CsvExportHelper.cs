using System.Globalization;
using System.Text;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Diagnostics;

/// <summary>
/// RFC 4180 CSV serializer with spreadsheet formula-injection neutralization
/// (prefixes cells starting with =, +, -, @, tab, or CR with a single quote).
/// </summary>
public static class CsvExportHelper
{
    public static string SanitizeAndEscapeCell(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var clean = value.Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ');
        var first = clean[0];
        if (first is '=' or '+' or '-' or '@' or '\t')
        {
            clean = "'" + clean;
        }

        if (clean.Contains(',') || clean.Contains('"'))
        {
            return "\"" + clean.Replace("\"", "\"\"") + "\"";
        }

        return clean;
    }

    public static string SerializeQueries(IEnumerable<LiveQueryMonitorEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var sb = new StringBuilder(4096);
        sb.AppendLine("Timestamp,Domain,RecordType,Outcome,ResponseCode,AnswerSummary,MatchedRule,ResolverName,Protocol,LatencyMs");
        foreach (var e in entries)
        {
            sb.Append(SanitizeAndEscapeCell(e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture))).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.Domain)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.RecordType)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.Outcome)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.ResponseCode)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.AnswerSummary)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.MatchedRule)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.ResolverName)).Append(',');
            sb.Append(SanitizeAndEscapeCell(e.Protocol.ToString())).Append(',');
            sb.AppendLine(e.LatencyMs.HasValue
                ? e.LatencyMs.Value.ToString("0.0", CultureInfo.InvariantCulture)
                : string.Empty);
        }

        return sb.ToString();
    }

    public static string SerializeDomainAnalytics(IEnumerable<DomainQueryAggregate> aggregates)
    {
        ArgumentNullException.ThrowIfNull(aggregates);
        var sb = new StringBuilder(2048);
        sb.AppendLine("Domain,TotalCount,QueriesPerMinute,IsHighFrequency,BlockedCount,CachedCount,FailedCount,RoutedCount,RewrittenCount,AverageLatencyMs,LastOutcome,LastResolver,LastAnswer,LastSeenUtc");
        foreach (var a in aggregates)
        {
            sb.Append(SanitizeAndEscapeCell(a.Domain)).Append(',');
            sb.Append(a.TotalCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.QueriesPerMinute.ToString("0.0", CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.IsHighFrequency ? "True" : "False").Append(',');
            sb.Append(a.BlockedCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.CachedCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.FailedCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.RoutedCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.RewrittenCount.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(a.AverageLatencyMs.ToString("0.0", CultureInfo.InvariantCulture)).Append(',');
            sb.Append(SanitizeAndEscapeCell(a.LastOutcome)).Append(',');
            sb.Append(SanitizeAndEscapeCell(a.LastResolverName)).Append(',');
            sb.Append(SanitizeAndEscapeCell(a.LastAnswerSummary)).Append(',');
            sb.AppendLine(SanitizeAndEscapeCell(a.LastSeenUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)));
        }

        return sb.ToString();
    }
}

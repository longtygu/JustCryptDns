using System.Globalization;
using System.Text;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Generates a lightweight Proxy Auto-Config (PAC) script so Windows, browsers, and desktop apps
/// route only DPI-blocked or split-tunneled domains through the local proxy while game and normal traffic stay DIRECT.
/// </summary>
public static class PacScriptGenerator
{
    public static string Generate(BypassSettings settings, int activeProxyPort)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var port = activeProxyPort > 0 ? activeProxyPort : settings.ProxyPort;
        var address = string.IsNullOrWhiteSpace(settings.ListenAddress) ? "127.0.0.1" : settings.ListenAddress.Trim();
        if (address.Contains(':', StringComparison.Ordinal) && !address.StartsWith('['))
        {
            address = $"[{address}]";
        }

        var sb = new StringBuilder(2048);
        sb.AppendLine("function FindProxyForURL(url, host) {");
        sb.AppendLine("  if (!host) return 'DIRECT';");
        sb.AppendLine("  var h = host.toLowerCase();");
        sb.AppendLine("  var colon = h.indexOf(':');");
        sb.AppendLine("  if (colon > 0 && h.indexOf(':', colon + 1) < 0 && h.charAt(0) !== '[') h = h.substring(0, colon);");
        sb.AppendLine("  if (h.charAt(h.length - 1) === '.') h = h.substring(0, h.length - 1);");
        sb.AppendLine("  if (isPlainHostName(h) || h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]') return 'DIRECT';");
        sb.AppendLine("  if (shExpMatch(h, '127.*') || shExpMatch(h, '10.*') || shExpMatch(h, '192.168.*') || shExpMatch(h, '169.254.*')) return 'DIRECT';");
        sb.AppendLine("  if (/^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(h)) return 'DIRECT';");
        sb.AppendLine("  if (dnsDomainIs(h, '.local') || dnsDomainIs(h, '.lan')) return 'DIRECT';");

        foreach (var excl in settings.DirectExclusionDomains ?? [])
        {
            var norm = RoutingMatcher.NormalizeDomain(excl);
            if (!string.IsNullOrEmpty(norm))
            {
                AppendExclusionCheck(sb, norm);
            }
        }

        foreach (var rule in settings.Rules ?? [])
        {
            if (!rule.Enabled || rule.Mode != BypassMode.Direct)
            {
                continue;
            }

            var pat = RoutingMatcher.NormalizeDomain(rule.Pattern);
            if (!string.IsNullOrEmpty(pat))
            {
                AppendHostMatchCheck(sb, pat, rule.MatchKind, "'DIRECT'");
            }
        }

        sb.Append("  var proxy = 'PROXY ").Append(EscapeJs(address)).Append(':').Append(port.ToString(CultureInfo.InvariantCulture)).AppendLine("; DIRECT';");

        if (settings.WindowsProxyMode == WindowsProxyMode.GlobalSystemProxy
            || settings.CoverageMode == BypassCoverageMode.AllWebsitesSmart)
        {
            sb.AppendLine("  return proxy;");
            sb.AppendLine("}");
            return sb.ToString();
        }

        foreach (var rule in settings.Rules ?? [])
        {
            if (!rule.Enabled || rule.Mode == BypassMode.Direct)
            {
                continue;
            }

            var pat = RoutingMatcher.NormalizeDomain(rule.Pattern);
            if (!string.IsNullOrEmpty(pat))
            {
                AppendHostMatchCheck(sb, pat, rule.MatchKind, "proxy");
            }
        }

        sb.AppendLine("  return 'DIRECT';");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private static void AppendHostMatchCheck(StringBuilder sb, string pat, RoutingMatchKind matchKind, string resultExpr)
    {
        switch (matchKind)
        {
            case RoutingMatchKind.Exact:
                sb.Append("  if (h === '").Append(EscapeJs(pat)).Append("') return ").Append(resultExpr).AppendLine(";");
                break;
            case RoutingMatchKind.DomainSuffix:
                if (pat.StartsWith("*.", StringComparison.Ordinal))
                {
                    pat = pat[2..];
                }
                else if (pat.StartsWith('.'))
                {
                    pat = pat[1..];
                }

                if (!string.IsNullOrEmpty(pat))
                {
                    sb.Append("  if (h === '").Append(EscapeJs(pat)).Append("' || dnsDomainIs(h, '.").Append(EscapeJs(pat)).Append("')) return ").Append(resultExpr).AppendLine(";");
                }
                break;
            case RoutingMatchKind.Wildcard:
                if (pat.StartsWith("*.", StringComparison.Ordinal) && !pat[2..].Contains('*') && !pat[2..].Contains('?'))
                {
                    var root = pat[2..];
                    sb.Append("  if (h === '").Append(EscapeJs(root)).Append("' || dnsDomainIs(h, '.").Append(EscapeJs(root)).Append("')) return ").Append(resultExpr).AppendLine(";");
                }
                else
                {
                    sb.Append("  if (shExpMatch(h, '").Append(EscapeJs(pat)).Append("')) return ").Append(resultExpr).AppendLine(";");
                }
                break;
        }
    }

    private static void AppendExclusionCheck(StringBuilder sb, string norm)
    {
        if (norm.Contains('*') || norm.Contains('?'))
        {
            sb.Append("  if (shExpMatch(h, '").Append(EscapeJs(norm)).AppendLine("')) return 'DIRECT';");
        }
        else
        {
            sb.Append("  if (h === '").Append(EscapeJs(norm)).Append("' || dnsDomainIs(h, '.").Append(EscapeJs(norm)).AppendLine("')) return 'DIRECT';");
        }
    }

    private static string EscapeJs(string value) =>
        value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("'", "\\'", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal)
            .Replace("\0", string.Empty, StringComparison.Ordinal)
            .Replace("\u2028", string.Empty, StringComparison.Ordinal)
            .Replace("\u2029", string.Empty, StringComparison.Ordinal);
}

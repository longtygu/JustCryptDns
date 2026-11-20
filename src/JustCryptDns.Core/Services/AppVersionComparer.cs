using System.Globalization;

namespace JustCryptDns.Core.Services;

/// <summary>
/// Normalizes and compares SemVer strings (stripping leading <c>v</c> and <c>+build</c> metadata).
/// </summary>
public static class AppVersionComparer
{
    public static string NormalizeVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "0.0.0";
        }

        var trimmed = raw.Trim();
        if (trimmed.StartsWith('v') || trimmed.StartsWith('V'))
        {
            trimmed = trimmed[1..];
        }

        var plusIndex = trimmed.IndexOf('+');
        if (plusIndex >= 0)
        {
            trimmed = trimmed[..plusIndex];
        }

        return string.IsNullOrWhiteSpace(trimmed) ? "0.0.0" : trimmed.Trim();
    }

    public static bool IsNewer(string? candidate, string? current) => Compare(candidate, current) > 0;

    public static int Compare(string? left, string? right)
    {
        var (leftNums, leftPre) = Parse(left);
        var (rightNums, rightPre) = Parse(right);

        var maxLen = Math.Max(leftNums.Length, rightNums.Length);
        for (var i = 0; i < maxLen; i++)
        {
            var l = i < leftNums.Length ? leftNums[i] : 0;
            var r = i < rightNums.Length ? rightNums[i] : 0;
            if (l != r)
            {
                return l.CompareTo(r);
            }
        }

        if (leftPre.Length == 0 && rightPre.Length == 0)
        {
            return 0;
        }

        if (leftPre.Length == 0)
        {
            return 1; // Stable > prerelease
        }

        if (rightPre.Length == 0)
        {
            return -1;
        }

        var maxPre = Math.Max(leftPre.Length, rightPre.Length);
        for (var i = 0; i < maxPre; i++)
        {
            if (i >= leftPre.Length)
            {
                return -1;
            }

            if (i >= rightPre.Length)
            {
                return 1;
            }

            var a = leftPre[i];
            var b = rightPre[i];
            var aIsNum = int.TryParse(a, NumberStyles.None, CultureInfo.InvariantCulture, out var aNum);
            var bIsNum = int.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out var bNum);

            int cmp;
            if (aIsNum && bIsNum)
            {
                cmp = aNum.CompareTo(bNum);
            }
            else if (aIsNum != bIsNum)
            {
                cmp = aIsNum ? -1 : 1; // Numeric < alphanumeric per SemVer 2.0
            }
            else
            {
                cmp = string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
            }

            if (cmp != 0)
            {
                return cmp;
            }
        }

        return 0;
    }

    private static (int[] Numbers, string[] Prerelease) Parse(string? raw)
    {
        var norm = NormalizeVersion(raw);
        var dashIndex = norm.IndexOf('-');
        var corePart = dashIndex >= 0 ? norm[..dashIndex] : norm;
        var prePart = dashIndex >= 0 ? norm[(dashIndex + 1)..] : string.Empty;

        var rawSegments = corePart.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var nums = new int[rawSegments.Length];
        for (var i = 0; i < rawSegments.Length; i++)
        {
            _ = int.TryParse(rawSegments[i], NumberStyles.None, CultureInfo.InvariantCulture, out nums[i]);
        }

        var pre = string.IsNullOrWhiteSpace(prePart)
            ? []
            : prePart.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return (nums, pre);
    }
}

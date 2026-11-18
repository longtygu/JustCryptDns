using System.Globalization;
using System.Net;
using System.Windows;
using System.Windows.Data;

namespace JustCryptDns.App.Converters;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is true;
        return flag ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Visibility v && (v == Visibility.Visible) ^ Invert;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var hasValue = value is not null && (value is not string s || s.Length > 0);
        return hasValue ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Negates a boolean value.</summary>
public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not true;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not true;
}

/// <summary>Two-way binding of a bool property to a RadioButton: ConverterParameter is "True" or "False".</summary>
public sealed class BoolEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is bool b && parameter is string p && bool.TryParse(p, out var expected) && b == expected;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true && parameter is string p && bool.TryParse(p, out var expected) ? expected : Binding.DoNothing;
}

/// <summary>Two-way binding of an enum property to a RadioButton: ConverterParameter is the enum member name.</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not null && parameter is string p && string.Equals(value.ToString(), p, StringComparison.Ordinal);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true && parameter is string p ? Enum.Parse(targetType, p) : Binding.DoNothing;
}

/// <summary>Responsive column count for card grids based on available width.</summary>
public sealed class WidthToColumnsConverter : IValueConverter
{
    public double TwoColumnMin { get; set; } = 420;

    public double FourColumnMin { get; set; } = 760;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var width = value is double d ? d : 0;
        return width >= FourColumnMin ? 4 : width >= TwoColumnMin ? 2 : 1;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>values[0] = has snapshot (bool), values[1] = adapter; visible when a snapshot exists without an adapter.</summary>
public sealed class NoAdapterVisibilityConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture) =>
        values.Length == 2 && values[0] is true && values[1] is null ? Visibility.Visible : Visibility.Collapsed;

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Formats a list of IP addresses one per line.</summary>
public sealed class AddressListConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is IEnumerable<IPAddress> list ? string.Join(Environment.NewLine, list.Select(a => a.ToString())) : string.Empty;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Formats bits per second as a human readable link speed.</summary>
public sealed class LinkSpeedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not long bps || bps <= 0)
        {
            return "—";
        }

        return bps >= 1_000_000_000
            ? string.Create(culture, $"{bps / 1_000_000_000.0:0.#} Gbps")
            : string.Create(culture, $"{bps / 1_000_000.0:0.#} Mbps");
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

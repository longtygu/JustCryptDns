using System.Globalization;
using System.Windows.Data;
using System.Windows.Markup;

namespace JustCryptDns.App.Localization;

/// <summary>
/// <c>Text="{l:Loc Nav_Dashboard}"</c> — binds to a localized string that updates when the language changes.
/// </summary>
[MarkupExtensionReturnType(typeof(object))]
public sealed class LocExtension : MarkupExtension
{
    public LocExtension()
    {
    }

    public LocExtension(string key) => Key = key;

    [ConstructorArgument("key")]
    public string Key { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding($"[{Key}]")
        {
            Source = LocalizationManager.Instance,
            Mode = BindingMode.OneWay,
        };
        return binding.ProvideValue(serviceProvider);
    }
}

/// <summary>
/// Multi-binding converter: values[0] = resource key (string or enum), values[1] = culture (change trigger).
/// Optional ConverterParameter is a key prefix, e.g. <c>Theme_</c> + enum value.
/// </summary>
public sealed class LocKeyConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values.Length == 0 || values[0] is null || values[0] == System.Windows.DependencyProperty.UnsetValue)
        {
            return string.Empty;
        }

        var key = (parameter as string ?? string.Empty) + values[0];
        return LocalizationManager.Instance.Get(key);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Multi-binding converter: ConverterParameter = resource key of a format string, values[0] = argument,
/// values[1] = culture (change trigger). DateTimeOffset arguments are rendered as local time.
/// </summary>
public sealed class LocFormatConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (parameter is not string key || values.Length == 0 || values[0] is null || values[0] == System.Windows.DependencyProperty.UnsetValue)
        {
            return string.Empty;
        }

        var manager = LocalizationManager.Instance;
        object arg = values[0] is DateTimeOffset dto ? dto.LocalDateTime.ToString("T", manager.Culture) : values[0];
        return manager.Format(key, arg);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

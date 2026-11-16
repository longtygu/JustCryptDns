namespace JustCryptDns.App.ViewModels;

/// <summary>
/// Honest placeholder for modules scheduled in a later phase: shows the roadmap, never fake data or controls.
/// </summary>
public sealed class PlannedFeatureViewModel : PageViewModel
{
    public PlannedFeatureViewModel(string pageKey, int phase, int featureCount)
        : base($"Nav_{pageKey}", $"Page_{pageKey}_Subtitle")
    {
        Phase = phase;
        FeatureKeys = Enumerable.Range(1, featureCount).Select(i => $"Planned_{pageKey}_{i}").ToList();
    }

    public int Phase { get; }

    public IReadOnlyList<string> FeatureKeys { get; }
}

using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Claims;
using Util.AuthorizationHelper.Policies;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Presents the app's policy definitions to the minting core as plain permission strings.
/// </summary>
/// <remarks>
/// App-internal claims are <c>(TStandard.Namespace, permissionName)</c> pairs, so translating in either direction
/// is just adding or removing the namespace. Claims belonging to some other namespace are ignored rather than
/// surfaced: they are not permissions this app can mint, and offering them would only produce keys that do not work.
/// </remarks>
/// <typeparam name="TStandard">The app-internal auth standard, which owns the claim namespace.</typeparam>
/// <typeparam name="TPolicyContainer">The type declaring the app's policies.</typeparam>
public sealed class PolicyRequirementCatalog<TStandard, TPolicyContainer> : IPolicyRequirementCatalog
    where TStandard : IInternalAuthStandard
    where TPolicyContainer : IStaticPolicyDefinitionContainer
{
    private readonly Dictionary<string, IReadOnlyList<IReadOnlySet<string>>> _byPolicyName;

    /// <summary>
    /// Reads the policy definitions once, at construction. They are static by design, so there is nothing to refresh.
    /// </summary>
    public PolicyRequirementCatalog()
    {
        var definitions = TPolicyContainer.ContainedPolicyDefinitions;

        _byPolicyName = definitions.ToDictionary(
            policy => policy.Name,
            policy => (IReadOnlyList<IReadOnlySet<string>>)policy.ClaimRequirementAlternatives
                .Select(alternative => (IReadOnlySet<string>)alternative.RequiredClaims
                    .Where(IsOwnedByThisStandard)
                    .Select(claim => claim.Value)
                    .ToHashSet(StringComparer.Ordinal))
                .ToArray(),
            StringComparer.Ordinal);

        KnownPermissions = definitions
            .SelectMany(policy => policy.ClaimRequirementAlternatives)
            .SelectMany(alternative => alternative.RequiredClaims)
            .Where(IsOwnedByThisStandard)
            .Select(claim => claim.Value)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string> KnownPolicyNames => _byPolicyName.Keys;

    /// <inheritdoc />
    public IReadOnlyCollection<string> KnownPermissions { get; }

    /// <inheritdoc />
    public bool TryGetRequirementAlternatives(string policyName, out IReadOnlyList<IReadOnlySet<string>> alternatives)
        => _byPolicyName.TryGetValue(policyName, out alternatives!);

    /// <summary>The claim carrying a given permission, ready to be handed to the identity generator.</summary>
    public static ClaimDefinition ToClaim(string permission) => new(TStandard.Namespace, permission);

    private static bool IsOwnedByThisStandard(ClaimDefinition claim)
        => string.Equals(claim.ClaimType, TStandard.Namespace, StringComparison.Ordinal);
}

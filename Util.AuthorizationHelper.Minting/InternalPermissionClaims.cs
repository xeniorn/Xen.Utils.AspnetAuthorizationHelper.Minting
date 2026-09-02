using Util.AuthorizationHelper.Claims;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Translates between app-internal claims and the plain permission strings the minting core works in.
/// </summary>
/// <remarks>
/// An app-internal claim is <c>(TStandard.Namespace, permissionName)</c> - see
/// <see cref="AppInternalClaimDefinition{TStandard}"/> - so this is only ever adding or removing the namespace.
/// It exists as its own type because both the catalog and the claim extractor need it, and neither should have to
/// know about the other.
/// </remarks>
/// <typeparam name="TStandard">The app-internal auth standard owning the claim namespace.</typeparam>
public static class InternalPermissionClaims<TStandard>
    where TStandard : IInternalAuthStandard
{
    /// <summary>The claim carrying a permission.</summary>
    public static ClaimDefinition ToClaim(string permission) => new(TStandard.Namespace, permission);

    /// <summary>Whether a claim is one of this standard's permissions, as opposed to some unrelated claim.</summary>
    public static bool IsPermissionClaim(ClaimDefinition claim)
        => string.Equals(claim.ClaimType, TStandard.Namespace, StringComparison.Ordinal);

    /// <summary>
    /// The permission a claim carries, or null when the claim belongs to some other namespace. Claims from
    /// elsewhere are dropped rather than surfaced - they are not permissions this app can mint, and offering them
    /// would only produce keys that do not work.
    /// </summary>
    public static string? ToPermissionOrNull(ClaimDefinition claim)
        => IsPermissionClaim(claim) ? claim.Value : null;
}

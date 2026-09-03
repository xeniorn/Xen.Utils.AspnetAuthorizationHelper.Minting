using System.Security.Claims;
using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Principals;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Turns a principal into the caller the minting service reasons about: which subjects they hold, and whether
/// they may act for subjects they do not.
/// </summary>
/// <remarks>
/// The admin-like claim of <typeparamref name="TStandard"/> is what lifts the restriction, matching how that claim
/// already behaves everywhere else - an <c>AdminOverrideAuthorizationHandler</c> holder passes every policy in the
/// app, so being unable to mint on a role's behalf would have been the odd exception rather than a safeguard.
/// Someone who can edit grants can reach the same place by writing a grant for their own role first; this only
/// removes the detour, and leaves the audit trail on the key instead of on a throwaway grant.
///
/// It widens whose grants may be drawn on, never what a grant permits. The deny list still applies, the target
/// subject's grants still decide the permissions and the lifetime, and the key still dies when they go.
/// </remarks>
public sealed class MintingCallerFactory<TStandard>(SubjectSelectorExtractor subjects)
    where TStandard : IInternalAuthStandard
{
    /// <summary>Whether this principal may mint under a subject it does not hold.</summary>
    public static bool MayActAsAnySubject(ClaimsPrincipal? principal)
        => TStandard.SpecialAdminLikeClaim is { } claim && principal?.HasClaim(claim) == true;

    /// <summary>The caller, as the minting service wants it.</summary>
    public MintingCaller Create(ClaimsPrincipal principal)
        => new(subjects.Extract(principal), MayActAsAnySubject(principal));
}

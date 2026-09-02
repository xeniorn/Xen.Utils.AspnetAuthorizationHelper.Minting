using System.Security.Claims;
using Util.ApiKeyMinting;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Reads the subjects a caller holds - the things grants can be written against.
/// </summary>
/// <remarks>
/// <para>
/// Restricted to an allow-list of claim types, because the alternative is that every claim in a token becomes a
/// potential grant subject. A grant written against, say, <c>aud</c> or <c>iss</c> would be held by everyone.
/// </para>
/// <para>
/// App roles are the sensible default: they are named by the application rather than the directory, they survive
/// a caller belonging to many groups (large group memberships get replaced by a lookup reference in the token
/// rather than listed), and a whole group can be assigned to one, so department-wide delegation still works.
/// </para>
/// </remarks>
public sealed class SubjectSelectorExtractor(SubjectSelectorExtractor.MyOptions? options = null)
{
    private readonly MyOptions _options = options ?? new MyOptions();

    /// <summary>Configuration for the extractor.</summary>
    public class MyOptions
    {
        /// <summary>
        /// Claim types that may be used as grant subjects. Defaults to app roles only.
        /// </summary>
        public IReadOnlyCollection<string> SubjectClaimTypes { get; set; } = [DefaultRoleClaimType];
    }

    /// <summary>The claim type Entra and friends put app roles in.</summary>
    public const string DefaultRoleClaimType = "roles";

    /// <summary>
    /// Every subject the principal holds, de-duplicated. A caller holding two roles can mint under either, and
    /// their grants combine - see the union rule in the minting authority.
    /// </summary>
    public IReadOnlyList<SubjectSelector> Extract(ClaimsPrincipal principal)
    {
        var allowed = _options.SubjectClaimTypes.ToHashSet(StringComparer.OrdinalIgnoreCase);

        return principal.Claims
            .Where(x => allowed.Contains(x.Type))
            .Select(x => new SubjectSelector(x.Type, x.Value))
            .Distinct()
            .ToArray();
    }

    /// <summary>Whether the principal holds a particular subject; the check made before minting under it.</summary>
    public bool Holds(ClaimsPrincipal principal, SubjectSelector subject)
        => Extract(principal).Contains(subject);
}

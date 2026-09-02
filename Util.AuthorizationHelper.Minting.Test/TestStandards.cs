using Util.AuthorizationHelper.Claims;
using Util.AuthorizationHelper.Policies;

namespace Util.AuthorizationHelper.Minting.Test;

/// <summary>
/// A stand-in app-internal auth standard, shaped like a real one.
/// </summary>
public abstract class TestAuthStandard : IInternalAuthStandard
{
    public const string TestNamespace = "test_permissions_ns";

    public static string AuthenticationTypeName => "TestInternal";
    public static string Namespace => TestNamespace;
    public static ClaimDefinition? SpecialAdminLikeClaim { get; } = new(TestNamespace, "HasAdminLikeAccess");
    public static Type MyType => typeof(TestAuthStandard);
}

/// <summary>A permission claim in the test standard's namespace.</summary>
public sealed record TestPermission(string Name) : AppInternalClaimDefinition<TestAuthStandard>(Name);

/// <summary>
/// Policies covering the shapes the catalog has to cope with: a single claim, a requirement with no claims at
/// all, and a claim from a foreign namespace.
/// </summary>
public abstract class TestPolicySet : IStaticPolicyDefinitionContainer
{
    public static IReadOnlyCollection<InternalPolicyDefinition> ContainedPolicyDefinitions =>
        PolicyContainerHelper.GetAllInternalPolicyDefinitionsInType(typeof(TestPolicySet));

    public static readonly InternalPolicyDefinition<TestAuthStandard> CanViewBillingInfo = new(
        "CanViewBillingInfo", "View billing.", new TestPermission("CanViewBillingInfo"));

    public static readonly InternalPolicyDefinition<TestAuthStandard> CanEditBillingInfo = new(
        "CanEditBillingInfo", "Edit billing.", new TestPermission("CanEditBillingInfo"));

    /// <summary>Modelled exactly like a real "allow anonymous": one alternative, requiring no claims.</summary>
    public static readonly InternalPolicyDefinition<TestAuthStandard> AllowAnonymous = new(
        "AllowAnonymous",
        "Everyone.",
        new InternalPolicyDefinition<TestAuthStandard>.ClaimRequirement([]));

    /// <summary>
    /// Declared through the non-generic base on purpose: the generic form only accepts claims belonging to its own
    /// standard, so a foreign-namespace requirement cannot be expressed there at all. Reaching for the base type
    /// is the only way to produce one, and the catalog still has to cope with it.
    /// </summary>
    public static readonly InternalPolicyDefinition ForeignClaimPolicy = new(
        "ForeignClaimPolicy",
        "Requires something outside this standard.",
        new InternalPolicyDefinition.ClaimRequirement(
            [new ClaimDefinition("some_other_namespace", "SomethingElse")]));
}

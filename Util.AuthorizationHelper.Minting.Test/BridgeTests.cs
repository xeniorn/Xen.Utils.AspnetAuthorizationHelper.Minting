using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Authentication;

namespace Util.AuthorizationHelper.Minting.Test;

/// <summary>
/// The stored hash must equal what the authentication handler will emit for the same key. If these ever diverge,
/// minted keys authenticate perfectly and then match nothing - a failure that looks nothing like its cause, which
/// is why it is pinned here rather than left to integration testing.
/// </summary>
public class StandardApiKeyHasherTests
{
    /// <summary>
    /// The claim the handler emits for the standard's primary digest - the one a hasher derived from that standard
    /// produces. A standard may emit several claims; only the primary one is what gets stored.
    /// </summary>
    private static string PrimaryClaimValueFromHandler<TStandard>(string apiKey)
        where TStandard : ISpecApiAuthStandards
    {
        var request = new DefaultHttpRequest(new DefaultHttpContext())
        {
            Headers = { [TStandard.DefaultHeaderName] = apiKey }
        };

        var ticket = SpecApiAuthHandler<TStandard>.GetAuthenticationTicketFromRequest(request, NullLogger.Instance);

        return ticket!.Principal.Identities.Single().Claims
            .Single(x => x.Type == TStandard.DefaultClaimType)
            .Value;
    }

    [Fact]
    public void V2026_HashMatchesWhatTheHandlerEmits()
    {
        var apiKey = new Base64UrlApiKeyGenerator("ptk_").Generate();

        var stored = new StandardApiKeyHasher<SpecApiAuthStandardsV2026>().Hash(apiKey);

        Assert.Equal(PrimaryClaimValueFromHandler<SpecApiAuthStandardsV2026>(apiKey), stored);
    }

    [Fact]
    public void Md5_HashMatchesWhatTheHandlerEmits()
    {
        var apiKey = new Base64UrlApiKeyGenerator("ptk_").Generate();

        var stored = new StandardApiKeyHasher<SpecApiAuthStandardsV2026_Md5>().Hash(apiKey);

        Assert.Equal(PrimaryClaimValueFromHandler<SpecApiAuthStandardsV2026_Md5>(apiKey), stored);
    }

    /// <summary>
    /// The algorithm id is stored on every key, so a store written under one digest is distinguishable from a
    /// store written under another.
    /// </summary>
    [Fact]
    public void DefaultAlgorithmIdDistinguishesTheDigests()
    {
        Assert.NotEqual(
            new StandardApiKeyHasher<SpecApiAuthStandardsV2026_Md5>().DefaultAlgorithmId,
            new StandardApiKeyHasher<SpecApiAuthStandardsV2026>().DefaultAlgorithmId);
    }

    /// <summary>
    /// A standard emitting several digests can hash under any of them, and each result equals the claim the
    /// handler emits for that digest. That correspondence is what lets a key record which algorithm it used and
    /// still be found from the identity later.
    /// </summary>
    [Fact]
    public void EveryDigestOfTheStandardHashesToItsOwnClaim()
    {
        var apiKey = new Base64UrlApiKeyGenerator("ptk_").Generate();
        var hasher = new StandardApiKeyHasher<SpecApiAuthStandardsV2026>();

        var request = new DefaultHttpRequest(new DefaultHttpContext())
        {
            Headers = { [SpecApiAuthStandardsV2026.DefaultHeaderName] = apiKey }
        };
        var claims = SpecApiAuthHandler<SpecApiAuthStandardsV2026>
            .GetAuthenticationTicketFromRequest(request, NullLogger.Instance)!
            .Principal.Identities.Single().Claims.ToArray();

        Assert.Equal(2, hasher.AlgorithmIds.Count);

        foreach (var algorithmId in hasher.AlgorithmIds)
        {
            var emitted = claims.Single(x => x.Type == algorithmId).Value;
            Assert.Equal(emitted, hasher.Hash(apiKey, algorithmId));
        }
    }

    /// <summary>Naming a digest the standard does not emit is a mistake, not a silent fallback.</summary>
    [Fact]
    public void HashingUnderAnUnknownAlgorithm_Throws()
    {
        var hasher = new StandardApiKeyHasher<SpecApiAuthStandardsV2026>();

        Assert.Throws<ArgumentOutOfRangeException>(() => hasher.Hash("ptk_whatever", "sha3-nope"));
    }

    /// <summary>The default must be the primary digest, so new keys do not silently land on the legacy one.</summary>
    [Fact]
    public void DefaultAlgorithmIsThePrimaryDigest()
    {
        var hasher = new StandardApiKeyHasher<SpecApiAuthStandardsV2026>();

        Assert.Equal(SpecApiAuthStandardsV2026.Sha256.ClaimType, hasher.DefaultAlgorithmId);
        Assert.Contains(SpecApiAuthStandardsV2026_Md5.MyDefaultClaimType, hasher.AlgorithmIds);
    }

    /// <summary>
    /// A key minted under the v2026 standard is still matchable by an md5-keyed store, because the handler emits
    /// that digest too. This is what lets both stores live under one scheme.
    /// </summary>
    [Fact]
    public void AKeyAlsoCarriesTheLegacyDigest()
    {
        var apiKey = new Base64UrlApiKeyGenerator("ptk_").Generate();

        var md5 = new StandardApiKeyHasher<SpecApiAuthStandardsV2026_Md5>().Hash(apiKey);

        var request = new DefaultHttpRequest(new DefaultHttpContext())
        {
            Headers = { [SpecApiAuthStandardsV2026.DefaultHeaderName] = apiKey }
        };
        var ticket = SpecApiAuthHandler<SpecApiAuthStandardsV2026>
            .GetAuthenticationTicketFromRequest(request, NullLogger.Instance);

        Assert.Contains(ticket!.Principal.Identities.Single().Claims,
            x => x.Type == SpecApiAuthStandardsV2026_Md5.MyDefaultClaimType && x.Value == md5);
    }

    [Fact]
    public void GeneratedKeysAreDistinctAndCarryThePrefix()
    {
        var generator = new Base64UrlApiKeyGenerator("ptk_");

        var keys = Enumerable.Range(0, 100).Select(_ => generator.Generate()).ToArray();

        Assert.All(keys, x => Assert.StartsWith("ptk_", x));
        Assert.Equal(100, keys.Distinct().Count());
    }
}

public class PolicyRequirementCatalogTests
{
    private readonly PolicyRequirementCatalog<TestAuthStandard, TestPolicySet> _sut = new();

    [Fact]
    public void PolicyResolvesToItsPermission()
    {
        Assert.True(_sut.TryGetRequirementAlternatives("CanViewBillingInfo", out var alternatives));

        Assert.Equal(["CanViewBillingInfo"], Assert.Single(alternatives));
    }

    /// <summary>
    /// An "allow anonymous" policy is one alternative containing no claims - not zero alternatives. The
    /// distinction survives the translation, because the resolver treats the two differently.
    /// </summary>
    [Fact]
    public void AllowAnonymous_IsOneAlternativeThatRequiresNothing()
    {
        Assert.True(_sut.TryGetRequirementAlternatives("AllowAnonymous", out var alternatives));

        Assert.Empty(Assert.Single(alternatives));
    }

    [Fact]
    public void ClaimsFromAnotherNamespace_AreNotOfferedAsPermissions()
    {
        Assert.True(_sut.TryGetRequirementAlternatives("ForeignClaimPolicy", out var alternatives));

        Assert.Empty(Assert.Single(alternatives));
        Assert.DoesNotContain("SomethingElse", _sut.KnownPermissions);
    }

    [Fact]
    public void KnownPermissionsCoverTheDeclaredPolicies()
    {
        Assert.Contains("CanViewBillingInfo", _sut.KnownPermissions);
        Assert.Contains("CanEditBillingInfo", _sut.KnownPermissions);
    }

    [Fact]
    public void UnknownPolicy_IsReportedRatherThanThrown()
    {
        Assert.False(_sut.TryGetRequirementAlternatives("NoSuchPolicy", out _));
    }

    [Fact]
    public void PermissionRoundTripsThroughItsClaim()
    {
        var claim = InternalPermissionClaims<TestAuthStandard>.ToClaim("CanViewBillingInfo");

        Assert.Equal(TestAuthStandard.Namespace, claim.ClaimType);
        Assert.Equal("CanViewBillingInfo", InternalPermissionClaims<TestAuthStandard>.ToPermissionOrNull(claim));
    }
}

public class SubjectSelectorExtractorTests
{
    private static ClaimsPrincipal PrincipalWith(params (string Type, string Value)[] claims)
        => new(new ClaimsIdentity(claims.Select(x => new Claim(x.Type, x.Value)), "test"));

    [Fact]
    public void RolesAreExtractedByDefault()
    {
        var subjects = new SubjectSelectorExtractor().Extract(
            PrincipalWith(("roles", "Billing"), ("roles", "Instruments")));

        Assert.Equal(
            [new SubjectSelector("roles", "Billing"), new SubjectSelector("roles", "Instruments")],
            subjects);
    }

    /// <summary>
    /// Without the allow-list, a grant could be written against something every caller carries - an audience or an
    /// issuer - and would then be held by everyone.
    /// </summary>
    [Fact]
    public void ClaimTypesOutsideTheAllowListAreIgnored()
    {
        var subjects = new SubjectSelectorExtractor().Extract(
            PrincipalWith(("roles", "Billing"), ("aud", "api://something"), ("iss", "https://login")));

        Assert.Equal([new SubjectSelector("roles", "Billing")], subjects);
    }

    [Fact]
    public void AdditionalClaimTypesCanBeAllowed()
    {
        var options = new SubjectSelectorExtractor.MyOptions { SubjectClaimTypes = ["roles", "preferred_username"] };

        var subjects = new SubjectSelectorExtractor(options).Extract(
            PrincipalWith(("preferred_username", "someone@example.org"), ("aud", "ignored")));

        Assert.Equal([new SubjectSelector("preferred_username", "someone@example.org")], subjects);
    }

    [Fact]
    public void HoldsIsTrueOnlyForSubjectsThePrincipalActuallyCarries()
    {
        var extractor = new SubjectSelectorExtractor();
        var principal = PrincipalWith(("roles", "Billing"));

        Assert.True(extractor.Holds(principal, new SubjectSelector("roles", "Billing")));
        Assert.False(extractor.Holds(principal, new SubjectSelector("roles", "Instruments")));
    }
}


/// <summary>
/// Who may act for a subject they do not hold.
/// </summary>
public class MintingCallerFactoryTests
{
    private static readonly MintingCallerFactory<TestAuthStandard> Sut = new(new SubjectSelectorExtractor());

    private static ClaimsPrincipal PrincipalWith(params (string Type, string Value)[] claims)
        => new(new ClaimsIdentity(claims.Select(x => new Claim(x.Type, x.Value)), "test"));

    [Fact]
    public void AnOrdinaryCallerHoldsOnlyItsOwnSubjects()
    {
        var caller = Sut.Create(PrincipalWith(("roles", "Billing")));

        Assert.Equal([new SubjectSelector("roles", "Billing")], caller.Subjects);
        Assert.False(caller.MayActAsAnySubject);
    }

    /// <summary>
    /// The admin-like claim already passes every policy in the app through the override handler, so it lifts this
    /// restriction too rather than leaving minting as the one place it does not reach.
    /// </summary>
    [Fact]
    public void TheAdminLikeClaimLiftsTheSubjectRestriction()
    {
        var caller = Sut.Create(PrincipalWith(
            ("roles", "Billing"), (TestAuthStandard.TestNamespace, "HasAdminLikeAccess")));

        Assert.True(caller.MayActAsAnySubject);
        Assert.Equal([new SubjectSelector("roles", "Billing")], caller.Subjects);
    }

    /// <summary>The claim only counts in the standard's own namespace, not by bare name.</summary>
    [Fact]
    public void TheSameNameInAnotherNamespaceDoesNot()
    {
        var caller = Sut.Create(PrincipalWith(("roles", "Billing"), ("someone_elses_ns", "HasAdminLikeAccess")));

        Assert.False(caller.MayActAsAnySubject);
    }

    [Fact]
    public void AnAdminHoldingNoRolesCanStillActForOthers()
    {
        var caller = Sut.Create(PrincipalWith((TestAuthStandard.TestNamespace, "HasAdminLikeAccess")));

        Assert.Empty(caller.Subjects);
        Assert.True(caller.MayActAsAnySubject);
    }
}

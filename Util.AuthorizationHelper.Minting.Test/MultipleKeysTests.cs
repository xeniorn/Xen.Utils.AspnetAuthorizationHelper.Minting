using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Authentication;
using Util.AuthorizationHelper.Minting;

namespace Util.AuthorizationHelper.Minting.Test;

/// <summary>
/// A request may carry several keys (several header values). Each is resolved on its own and the claims are the union
/// of every key that works; an unusable key next to a working one costs nothing.
/// </summary>
public class MultipleKeysTests
{
    private const string Scope = "app";
    private static readonly SubjectSelector Billing = new("roles", "Billing");

    private readonly InMemoryKeys _keys = new();
    private readonly InMemoryGrants _grants = new();
    private readonly StandardApiKeyHasher<SpecApiAuthStandardsV2026> _hasher = new(new ApiKeyAlgorithmNaming());

    public MultipleKeysTests()
    {
        _grants.Grants.Add(new MintingGrant("g-view", Scope, Billing, "CanViewBilling", null, IsActive: true));
        _grants.Grants.Add(new MintingGrant("g-edit", Scope, Billing, "CanEditBilling", null, IsActive: true));
    }

    private string GivenKey(string id, string permission, DateTimeOffset? revoked = null)
    {
        var plaintext = $"ptk_{id}_{Guid.NewGuid():N}";
        _keys.Keys.Add(new MintedKey(id, Scope, _hasher.Hash(plaintext), _hasher.DefaultAlgorithmId,
            [new MintedKeyPermission(permission, null)], Billing, id, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30),
            RevokedUtc: revoked));
        return plaintext;
    }

    private async Task<string[]> PermissionsFor(params string[] presentedKeys)
    {
        var request = new DefaultHttpContext().Request;
        request.Headers[SpecApiAuthStandardsV2026.DefaultHeaderName] = new StringValues(presentedKeys);
        var principal = SpecApiAuthHandler<SpecApiAuthStandardsV2026>.GetAuthenticationTicketFromRequest(request, NullLogger.Instance)!.Principal;

        var extractor = new MintedKeyClaimExtractor<TestAuthStandard, SpecApiAuthStandardsV2026>(
            new MintedKeyAuthorizer(_keys, _grants, new MintingOptions()),
            new MintedKeyClaimExtractor<TestAuthStandard, SpecApiAuthStandardsV2026>.MyOptions { Scope = Scope },
            new ApiKeyAlgorithmNaming());

        return (await extractor.GetClaimDefinitions(principal, CancellationToken.None)).Select(c => c.Value).Order().ToArray();
    }

    [Fact]
    public async Task Two_working_keys_give_the_union_of_their_permissions()
    {
        var viewKey = GivenKey("view", "CanViewBilling");
        var editKey = GivenKey("edit", "CanEditBilling");

        Assert.Equal(["CanEditBilling", "CanViewBilling"], await PermissionsFor(viewKey, editKey));
    }

    [Fact]
    public async Task An_unusable_key_next_to_a_working_one_is_ignored()
    {
        var revokedKey = GivenKey("old", "CanEditBilling", revoked: DateTimeOffset.UtcNow.AddHours(-1));
        var viewKey = GivenKey("view", "CanViewBilling");

        Assert.Equal(["CanViewBilling"], await PermissionsFor(revokedKey, "ptk_unknown", viewKey));
    }

    private sealed class InMemoryGrants : IMintingGrantStore
    {
        public List<MintingGrant> Grants { get; } = [];

        public Task<IReadOnlyList<MintingGrant>> GetAllAsync(string scope, CancellationToken token = default)
            => Task.FromResult<IReadOnlyList<MintingGrant>>(Grants.Where(g => g.Scope == scope).ToList());

        public Task<MintingGrant?> GetAsync(string scope, string grantId, CancellationToken token = default)
            => Task.FromResult(Grants.FirstOrDefault(g => g.Scope == scope && g.Id == grantId));

        public Task UpsertAsync(MintingGrant grant, CancellationToken token = default) => throw new NotSupportedException();

        public Task SetActiveAsync(string scope, string grantId, bool isActive, string? actor, CancellationToken token = default)
            => throw new NotSupportedException();
    }

    private sealed class InMemoryKeys : IMintedKeyStore
    {
        public List<MintedKey> Keys { get; } = [];

        public Task<MintedKey?> FindByDigestAsync(string scope, IReadOnlyCollection<PresentedApiKeyDigest> presented, CancellationToken token = default)
            => Task.FromResult(Keys.FirstOrDefault(k => k.Scope == scope && presented.Any(p => p.AlgorithmId == k.HashAlgorithmId && p.Hash == k.KeyHash)));

        public Task<IReadOnlyList<MintedKey>> ListAsync(string scope, bool includeRevoked, CancellationToken token = default)
            => Task.FromResult<IReadOnlyList<MintedKey>>(Keys.Where(k => k.Scope == scope && (includeRevoked || !k.IsRevoked)).ToList());

        public Task AddAsync(MintedKey key, CancellationToken token = default)
        {
            Keys.Add(key);
            return Task.CompletedTask;
        }

        public Task RevokeAsync(string scope, string keyId, string? revokedBy, string? reason, DateTimeOffset revokedUtc, CancellationToken token = default)
            => throw new NotSupportedException();

        public Task TouchLastUsedAsync(string scope, string keyId, DateTimeOffset whenUtc, CancellationToken token = default) => Task.CompletedTask;
    }
}

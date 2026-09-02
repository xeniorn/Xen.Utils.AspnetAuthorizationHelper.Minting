using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Authentication;
using Util.AuthorizationHelper.Claims;
using Util.AuthorizationHelper.Claims.Extraction.Base.ApiKey;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Grants app-internal claims to requests carrying a minted api key.
/// </summary>
/// <remarks>
/// <para>
/// The sibling <see cref="SpecApiKeyMapBasedClaimExtractor{TClaimSet,TApiAuthStandard}"/> freezes its map at
/// construction, which is exactly right for keys that come from configuration and exactly wrong for minted ones:
/// a key issued a moment ago has to work, and a revoked one has to stop. So this asks the store every time and
/// lets the store decide what to cache.
/// </para>
/// <para>
/// It looks only at identities produced by <typeparamref name="TApiKeyStandard"/>'s scheme, so registering it
/// alongside the configuration-backed extractor is safe even when both read the same header - each sees only its
/// own standard's claim type.
/// </para>
/// </remarks>
/// <typeparam name="TStandard">The app-internal auth standard whose namespace the granted claims carry.</typeparam>
/// <typeparam name="TApiKeyStandard">The api key standard minted keys are hashed and presented under.</typeparam>
public sealed class MintedKeyClaimExtractor<TStandard, TApiKeyStandard>(
    MintedKeyAuthorizer authorizer,
    MintedKeyClaimExtractor<TStandard, TApiKeyStandard>.MyOptions options,
    ILogger<MintedKeyClaimExtractor<TStandard, TApiKeyStandard>>? logger = null)
    : SpecApiKeyClaimExtractor<TStandard, TApiKeyStandard>(options)
    where TStandard : IInternalAuthStandard
    where TApiKeyStandard : ISpecApiAuthStandards
{
    private readonly ILogger _logger = logger ?? (ILogger)NullLogger.Instance;

    /// <summary>
    /// Configuration for the extractor. The identity filter is inherited from the api key standard.
    /// </summary>
    public class MyOptions : IMyOptions
    {
        /// <summary>
        /// Which application instance's keys count here. Matches the scope keys were minted under, so several
        /// deployments can share a database without sharing credentials.
        /// </summary>
        public string Scope { get; set; } = string.Empty;
    }

    /// <inheritdoc />
    protected override async Task<IReadOnlyCollection<ClaimDefinition>> GetClaims(
        IReadOnlyCollection<ClaimsIdentity> identities, CancellationToken token = default)
    {
        var presentedHashes = identities
            .SelectMany(x => x.Claims)
            .Where(x => string.Equals(x.Type, TApiKeyStandard.DefaultClaimType, StringComparison.Ordinal))
            .Select(x => x.Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (presentedHashes.Length == 0) return [];

        var granted = new List<ClaimDefinition>();

        foreach (var hash in presentedHashes)
        {
            var authorization = await authorizer.AuthorizeAsync(options.Scope, hash, token);

            if (authorization.Status is MintedKeyStatus.NotFound)
            {
                // not ours - very likely a key belonging to the configuration-backed extractor
                continue;
            }

            if (authorization.Status is not MintedKeyStatus.Active)
            {
                _logger.LogInformation("Minted api key {keyId} presented but is {status}",
                    authorization.Key?.Id, authorization.Status);
                continue;
            }

            granted.AddRange(authorization.LivePermissions.Select(InternalPermissionClaims<TStandard>.ToClaim));
        }

        return granted;
    }
}

using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Authentication;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Hashes keys with the digests <typeparamref name="TApiKeyStandard"/> declares.
/// </summary>
/// <remarks>
/// <para>
/// Deriving these from the standard rather than naming an algorithm is what keeps a stored hash equal, by
/// construction, to the value <see cref="SpecApiAuthHandler{TApiKeyStandard}"/> will put in the claim when
/// someone presents that key. Hard-coding it on both sides works right up until one of them changes, and the
/// failure - keys that authenticate but match nothing - looks nothing like its cause.
/// </para>
/// <para>
/// A stored hash is recorded against the algorithm that made it - <c>sha256</c>, <c>md5</c> - which is what
/// <see cref="ApiKeyAlgorithmNaming"/> supplies. The digest is still found by walking the standard's own list, so
/// the round trip holds: the same digest that produced the stored hash is the one that produces the claim.
/// </para>
/// </remarks>
/// <typeparam name="TApiKeyStandard">The api key standard the host registered.</typeparam>
public sealed class StandardApiKeyHasher<TApiKeyStandard>(ApiKeyAlgorithmNaming naming) : IApiKeyHasher
    where TApiKeyStandard : ISpecApiAuthStandards
{
    private static IReadOnlyCollection<ApiKeyDigest> Digests => ISpecApiAuthStandards.DigestsOf<TApiKeyStandard>();

    /// <summary>
    /// The standard's primary digest, so a key minted without asking for one uses whatever the standard leads
    /// with - sha256 for the v2026 standard, not the legacy digest it also still emits.
    /// </summary>
    public string DefaultAlgorithmId => naming.IdFor(TApiKeyStandard.DefaultClaimType);

    /// <inheritdoc />
    public IReadOnlyCollection<string> AlgorithmIds => [.. Digests.Select(naming.IdFor)];

    /// <inheritdoc />
    public string Hash(string apiKey, string? algorithmId = null)
    {
        var wanted = algorithmId ?? DefaultAlgorithmId;

        var digest = Digests.FirstOrDefault(x => string.Equals(naming.IdFor(x), wanted, StringComparison.Ordinal))
            ?? throw new ArgumentOutOfRangeException(nameof(algorithmId), wanted,
                $"Not a digest of this standard. Known: {string.Join(", ", AlgorithmIds)}.");

        return digest.ToClaim(apiKey).Value;
    }
}

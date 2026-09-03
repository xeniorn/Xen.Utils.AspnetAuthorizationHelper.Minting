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
/// The algorithm ids are the digests' claim types, which is what makes the round trip work: a key stored under
/// one records that claim type, and the extractor finds it again by the claim of the same type on the identity.
/// </para>
/// </remarks>
/// <typeparam name="TApiKeyStandard">The api key standard the host registered.</typeparam>
public sealed class StandardApiKeyHasher<TApiKeyStandard> : IApiKeyHasher
    where TApiKeyStandard : ISpecApiAuthStandards
{
    private static IReadOnlyCollection<ApiKeyDigest> Digests => ISpecApiAuthStandards.DigestsOf<TApiKeyStandard>();

    /// <summary>
    /// The standard's primary digest, so a key minted without asking for one uses whatever the standard leads
    /// with - sha256 for the v2026 standard, not the legacy digest it also still emits.
    /// </summary>
    public string DefaultAlgorithmId => TApiKeyStandard.DefaultClaimType;

    /// <inheritdoc />
    public IReadOnlyCollection<string> AlgorithmIds { get; } = [.. Digests.Select(x => x.ClaimType)];

    /// <inheritdoc />
    public string Hash(string apiKey, string? algorithmId = null)
    {
        var wanted = algorithmId ?? DefaultAlgorithmId;

        var digest = Digests.FirstOrDefault(x => string.Equals(x.ClaimType, wanted, StringComparison.Ordinal))
            ?? throw new ArgumentOutOfRangeException(nameof(algorithmId), wanted,
                $"Not a digest of this standard. Known: {string.Join(", ", AlgorithmIds)}.");

        return digest.ToClaim(apiKey).Value;
    }
}

using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Authentication;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Hashes keys with whatever <typeparamref name="TApiKeyStandard"/> uses.
/// </summary>
/// <remarks>
/// The point of deriving it from the standard rather than naming an algorithm is that a stored hash is then, by
/// construction, the exact value <see cref="SpecApiAuthHandler{TApiKeyStandard}"/> will put in the claim when
/// someone presents that key. Hard-coding the algorithm on both sides would work right up until one of them
/// changed, and the failure - keys that authenticate but match nothing - looks nothing like its cause.
/// </remarks>
/// <typeparam name="TApiKeyStandard">The api key standard the host registered.</typeparam>
public sealed class StandardApiKeyHasher<TApiKeyStandard> : IApiKeyHasher
    where TApiKeyStandard : ISpecApiAuthStandards
{
    /// <inheritdoc />
    public string AlgorithmId => TApiKeyStandard.DefaultClaimType;

    /// <inheritdoc />
    public string Hash(string apiKey)
        => ISpecApiAuthStandards.StandardizedApiKeyClaim<TApiKeyStandard>(apiKey).Value;
}

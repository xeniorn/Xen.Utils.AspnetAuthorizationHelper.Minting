using Util.AuthorizationHelper.Authentication;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Names the hashing algorithms a key store records against its hashes.
/// </summary>
/// <remarks>
/// A digest of the authorization standard knows the claim type it travels in - <c>HasApiKeySha256Hash</c> - but
/// that is where the value goes, not how it was computed. A store recording "this hash is a HasApiKeySha256Hash"
/// is answering the wrong question, and the answer means nothing outside this framework. It records
/// <c>sha256</c> instead, and this is the translation.
///
/// The mapping lives here rather than on the digest itself because the standard is published separately; when it
/// grows an algorithm id of its own this can be dropped and the id read straight off the digest.
/// </remarks>
public sealed class ApiKeyAlgorithmNaming
{
    /// <summary>The algorithm id for a sha256 digest.</summary>
    public const string Sha256 = "sha256";

    /// <summary>The algorithm id for an md5 digest.</summary>
    public const string Md5 = "md5";

    /// <summary>
    /// Algorithm id per digest claim type. Defaults to the two the v2026 standard declares; a host with its own
    /// standard adds its own, and anything unmapped keeps its claim type as the id so nothing silently collides.
    /// </summary>
    public IDictionary<string, string> AlgorithmIdByClaimType { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [SpecApiAuthStandardsV2026.Sha256.ClaimType] = Sha256,
            [SpecApiAuthStandardsV2026.Md5.ClaimType] = Md5
        };

    /// <summary>What a hash produced by this digest is recorded as.</summary>
    public string IdFor(ApiKeyDigest digest) => IdFor(digest.ClaimType);

    /// <inheritdoc cref="IdFor(ApiKeyDigest)"/>
    public string IdFor(string claimType)
        => AlgorithmIdByClaimType.TryGetValue(claimType, out var id) ? id : claimType;
}

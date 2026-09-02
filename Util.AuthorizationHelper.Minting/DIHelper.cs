using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Util.ApiKeyMinting;
using Util.AuthorizationHelper.Authentication;
using Util.AuthorizationHelper.Claims.Extraction.Base;
using Util.AuthorizationHelper.Policies;

namespace Util.AuthorizationHelper.Minting;

/// <summary>
/// Registration for delegated api key minting.
/// </summary>
public static class DIHelper
{
    /// <summary>
    /// Wires up minting against the host's auth standard, api key standard and policy set.
    /// <para>
    /// The host must separately register: <see cref="IMintedKeyStore"/> and <see cref="IMintingGrantStore"/>
    /// (persistence is deliberately not this package's business), the api key authentication scheme for
    /// <typeparamref name="TApiKeyStandard"/>, and an <see cref="IEndpointPolicyCatalog"/> if callers should be
    /// able to pick endpoints rather than policies.
    /// </para>
    /// </summary>
    /// <typeparam name="TStandard">The app-internal auth standard.</typeparam>
    /// <typeparam name="TApiKeyStandard">The api key standard minted keys are presented under.</typeparam>
    /// <typeparam name="TPolicyContainer">The type declaring the app's policies.</typeparam>
    /// <param name="builder"></param>
    /// <param name="scope">
    /// Which application instance these keys belong to. Keys and grants are stored against it, so several
    /// deployments can share a database without sharing credentials.
    /// </param>
    /// <param name="configureMinting">Lifetimes and the never-mintable deny list.</param>
    /// <param name="configureSubjects">Which claim types may be used as grant subjects. Defaults to app roles.</param>
    /// <param name="keyPrefix">
    /// Prepended to generated keys. Part of the key and therefore hashed with it; it exists so secret scanners
    /// and log redaction have something to match on.
    /// </param>
    public static void AddApiKeyMinting<TStandard, TApiKeyStandard, TPolicyContainer>(
        this IHostApplicationBuilder builder,
        string scope,
        Action<MintingOptions>? configureMinting = null,
        Action<SubjectSelectorExtractor.MyOptions>? configureSubjects = null,
        string keyPrefix = "")
        where TStandard : IInternalAuthStandard
        where TApiKeyStandard : ISpecApiAuthStandards
        where TPolicyContainer : IStaticPolicyDefinitionContainer
    {
        var mintingOptions = new MintingOptions();

        // the admin-like claim is never mintable, always. Putting it in the deny list here rather than leaving it
        // to the host means no grants table can ever hand out permanent admin, whatever gets written into it later
        if (TStandard.SpecialAdminLikeClaim is { } adminClaim)
        {
            mintingOptions.NeverMintablePermissions = [adminClaim.Value];
        }

        configureMinting?.Invoke(mintingOptions);
        builder.Services.TryAddSingleton(mintingOptions);

        var subjectOptions = new SubjectSelectorExtractor.MyOptions();
        configureSubjects?.Invoke(subjectOptions);
        builder.Services.TryAddSingleton(new SubjectSelectorExtractor(subjectOptions));

        builder.Services.TryAddSingleton<IApiKeyHasher, StandardApiKeyHasher<TApiKeyStandard>>();
        builder.Services.TryAddSingleton<IApiKeyGenerator>(_ => new Base64UrlApiKeyGenerator(keyPrefix));
        builder.Services.TryAddSingleton<IPolicyRequirementCatalog, PolicyRequirementCatalog<TStandard, TPolicyContainer>>();

        builder.Services.TryAddSingleton<MintingAuthority>();
        builder.Services.TryAddSingleton<PermissionResolver>();
        builder.Services.TryAddSingleton<MintedKeyAuthorizer>();
        builder.Services.TryAddSingleton<MintingService>();

        builder.Services.TryAddSingleton(new MintedKeyClaimExtractor<TStandard, TApiKeyStandard>.MyOptions
        {
            Scope = scope
        });

        builder.Services.TryAddSingleton<MintedKeyClaimExtractor<TStandard, TApiKeyStandard>>();
        builder.Services.AddSingleton<IInternalClaimExtractor<TStandard>>(
            sp => sp.GetRequiredService<MintedKeyClaimExtractor<TStandard, TApiKeyStandard>>());
    }
}

# Xen.Utils.AspnetAuthorizationHelper.Minting

Joins [`Xen.Utils.ApiKeyMinting`](https://github.com/xeniorn/Xen.Utils.ApiKeyMinting) to
[`Xen.Utils.AspnetAuthorizationHelper`](https://github.com/xeniorn/Xen.AspnetUtils). The minting core deals in
plain strings and knows nothing about claims or ASP.NET; this package makes those strings into app-internal
claims, and back.

## What it does

| Type | Does |
| --- | --- |
| `StandardApiKeyHasher<TApiKeyStandard>` | Hashes keys with whatever the api key standard uses. |
| `PolicyRequirementCatalog<TStandard, TPolicyContainer>` | Your policy definitions, flattened to permission strings. |
| `MintedKeyClaimExtractor<TStandard, TApiKeyStandard>` | Grants app-internal claims to requests carrying a minted key. |
| `SubjectSelectorExtractor` | The subjects a caller holds — the things grants are written against. |
| `InternalPermissionClaims<TStandard>` | Permission string to claim, and back. |

## The part that earns its keep

`StandardApiKeyHasher` derives the hash from the api key standard rather than naming an algorithm. A stored hash
is then, by construction, the exact value `SpecApiAuthHandler` will put in the claim when someone presents that
key. Hard-coding the algorithm on both sides works right up until one of them changes, and the failure — keys that
authenticate perfectly and then match nothing — looks nothing like its cause. There is a test pinning it.

## Registering

```csharp
builder.AddSpecialApiKeyAuthentication<SpecApiAuthStandardsV2026>();

builder.AddApiKeyMinting<MyInternalAuthStandard, SpecApiAuthStandardsV2026, MyPolicyDefinitionSet>(
    scope: appInstanceKey,
    configureMinting: o => { /* lifetimes */ },
    configureSubjects: o => o.SubjectClaimTypes = ["roles"],
    keyPrefix: "ptk_");
```

You still register `IMintedKeyStore` and `IMintingGrantStore` yourself — persistence is deliberately not this
package's business either.

The admin-like claim of `TStandard`, if it declares one, is added to the never-mintable deny list automatically.
It belongs in code rather than in a grants table, so that no amount of later data entry can hand out permanent
admin.

Keys minted with `KeyValidity.FollowsMinter` (personal delegations, see `Xen.Utils.ApiKeyMinting`) also need an
`IMinterSubjectSource`, registered as a singleton (the authorizer is one). Without it those keys carry nothing.

## Subjects default to app roles

Grants are written against a claim type and value, and the default allow-list is `roles` alone. Roles are named by
your application rather than the directory, they do not fall off a token when someone belongs to a great many
groups, and a whole group can be assigned to one — so department-wide delegation still works. Without the
allow-list a grant could be written against something every caller carries, such as an audience or an issuer, and
would then be held by everyone.

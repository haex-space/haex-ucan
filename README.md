# @haex-space/ucan

UCAN-based capability tokens for haex space authorization.

Ed25519 signing, `did:key` identifiers, and orthogonal per-cap delegation for
haex space resources (`space:{id}`) and haex server resources
(`server:{did}`).

## Installation

```sh
pnpm add @haex-space/ucan
```

Runtime dependencies are zero — the package uses Web Crypto (`globalThis.crypto`).

## Concepts

A UCAN token binds an **issuer** (a `did:key`) to an **audience** (another
`did:key`) with a set of **capabilities** and an expiration. Tokens can
**delegate** — the audience of one token can become the issuer of a child
token, provided each capability in the child is present in the parent AND
marked `delegatable: true` on the parent.

### Space capabilities (orthogonal, per-cap)

Space capabilities are stored as arrays of `{cap, delegatable}` entries.
Each cap is held independently — there is no `admin ⊃ invite ⊃ write ⊃ read`
hierarchy. A token holding `write` does not imply `read`; hold both if both
are needed.

The canonical cap names, in wire order (do not reshuffle):

```ts
type SpaceCap = 'read' | 'write' | 'invite' | 'admin'
```

The `delegatable` flag on each entry controls whether that cap can be passed
to a downstream child. A leaf token with no children can safely set
`delegatable: false`.

### Server capabilities

Server capabilities remain plain strings (currently only `'server/relay'`).
Any token that holds at least one space-cap in its chain can delegate
`server/relay` — this is deliberate: sync-server relay authorization piggybacks
on space membership.

## Quick start

### Issue a token

```ts
import {
  createUcan,
  createWebCryptoSigner,
  publicKeyToDid,
  spaceCapabilitySet,
  spaceResource,
} from '@haex-space/ucan'

const { signer, publicKey } = await createWebCryptoSigner()
const issuerDid = publicKeyToDid(publicKey)

const token = await createUcan({
  issuer: issuerDid,
  audience: 'did:key:z6Mk...audience...',
  signer,
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
  capabilities: {
    [spaceResource('abc-123')]: spaceCapabilitySet()
      .read(true)
      .write(true)
      .build(),
  },
})
```

### Verify a token

```ts
import { validateUcan, createWebCryptoVerifier } from '@haex-space/ucan'

const verifier = createWebCryptoVerifier()

const result = await validateUcan({
  token,
  verifier,
  audience: myDid,
  resource: spaceResource('abc-123'),
  requiredCapability: 'write', // SpaceCap for space resources
  now: Math.floor(Date.now() / 1000),
})

if (!result.valid) throw new Error(result.reason)
```

For server delegations, pass the full `ServerCapability` string:

```ts
requiredCapability: 'server/relay'
```

### Query and attenuate

```ts
import {
  holdsSpaceCap,
  isSpaceCapDelegatable,
  enforceDelegatable,
  isSpaceCapValue,
} from '@haex-space/ucan'

const held = token.payload.cap[spaceResource('abc-123')]

if (isSpaceCapValue(held) && holdsSpaceCap(held, 'write')) {
  // token authorises `write` on this space
}

// Chain attenuation: child cap-set must be a subset of parent, and every
// child cap must be `delegatable: true` on the parent.
const err = enforceDelegatable(parentSet, childSet)
if (err) throw new Error(`${err.kind} for ${err.cap}`)
```

## Wire format

The `cap` map in a UCAN payload keys resources by prefix. Space entries hold
capability-set arrays; server entries hold capability strings.

```json
{
  "cap": {
    "space:abc-123": [
      { "cap": "read", "delegatable": true },
      { "cap": "write", "delegatable": false }
    ],
    "server:did:key:z6Mk...": "server/relay"
  }
}
```

This wire form is bit-exactly compatible with the Rust-side `CapabilitySet` in
`haex-vault/src-tauri/src/ucan/capability_set.rs`. Both sides
produce/consume the same canonical JSON — entries in `SPACE_CAP_ORDER`, no
duplicates, no `delegatable: undefined`.

## API reference

### Cap-set construction

- `spaceCapabilitySet()` — fluent builder. Chain `.read(bool)`, `.write(bool)`,
  `.invite(bool)`, `.admin(bool)`, then `.build()` to get a
  `SpaceCapabilitySet`.
- `spaceCapabilitySetFromEntries(entries)` — build from raw
  `CapEntry[]`. Deduplicates and canonicalises order.
- `spaceRolePreset(role)` — the preset set for a `SpaceRole` (see
  [Role presets](#role-presets)). Prefer this over hand-rolling a builder chain
  at a delegation site.

### Role presets

`spaceRolePreset(role)` returns the exact set every delegation path hands out.
`SPACE_ROLES` lists all five roles in table order.

| role | `read` | `write` | `invite` | `admin` |
|---|---|---|---|---|
| `reader` | `false` | — | — | — |
| `writer` | `false` | `false` | — | — |
| `inviter` | **`true`** | — | `true` | — |
| `admin` | `true` | `true` | `true` | **`false`** |
| `owner` | `true` | `true` | `true` | `true` |

A `—` means the capability is not held at all; every other cell is that entry's
`delegatable` bit.

**Invariant: if a set contains `invite`, every other cap in that set is
`delegatable: true` — except `admin`.** `enforceDelegatable` returns on the
first offender in `SPACE_CAP_ORDER`, so an inviter holding a non-delegatable
`read` would trip on `read` and be able to delegate nothing at all. `admin`
stays non-delegatable so only the `owner` row can mint further admins.
`reader` and `writer` keep `read(false)` on purpose — neither holds `invite`,
so neither reaches a delegation boundary.

Note the builder's boolean is `delegatable`, and calling a method at all
*grants* the cap. To withhold a cap, omit the call — `.write(false)` grants a
non-delegatable `write`, it does not withhold `write`.

### Query

- `holdsSpaceCap(set, cap)` — does the set contain `cap`?
- `isSpaceCapDelegatable(set, cap)` — is `cap` present and
  `delegatable: true`?
- `holdsServerCap(value, cap)` — server-side equivalent.

### Attenuation

- `enforceDelegatable(parent, child): DelegationError | null` —
  returns `null` on success; on failure, returns the first offender in
  `SPACE_CAP_ORDER` with `kind: 'missing' | 'not_delegatable'`.

### Discriminators (runtime type guards)

- `isSpaceCapValue(v)` — `v is SpaceCapabilitySet`. An array in which every
  element has a `cap` from `SPACE_CAP_ORDER` and a boolean `delegatable`.
  Validates entry shape only, not the sorted/duplicate-free invariant — use
  `spaceCapabilitySetFromEntries` for that.
- `isServerCapValue(v)` — `v is ServerCapability`.

### Resource-string helpers

- `spaceResource(id)` → `` `space:${id}` ``
- `serverResource(did)` → `` `server:${did}` ``
- `parseSpaceResource(str)` → `{ kind: 'space', id } | null`

### Constants

- `SpaceCaps` — `{ READ, WRITE, INVITE, ADMIN }`, values are the bare cap
  names (`'read' | 'write' | 'invite' | 'admin'`).
- `SPACE_ROLES` — the five `SpaceRole` names in preset-table order.
- `ServerCapabilities` — `{ RELAY: 'server/relay' }`.
- `SPACE_CAP_ORDER` — canonical wire order for entries; do not reshuffle.
- `DidAuthAction` — DID-auth action enum.

### Crypto

- `createWebCryptoSigner()` — generates an Ed25519 signer + public key.
- `createWebCryptoVerifier()` — verifier compatible with `did:key` inputs.
- `publicKeyToDid(bytes)` / `didToRawPublicKey(did)` — did:key conversion.

## Testing

```sh
pnpm test        # vitest run
pnpm typecheck   # tsc --noEmit
pnpm build       # tsup → dist/
```

## Versioning

This package follows semver. See [CHANGELOG.md](./CHANGELOG.md) for the
`0.1.x → 0.2.0` migration guide and the `0.3.0` notes on role presets and the
tightened `isSpaceCapValue`.

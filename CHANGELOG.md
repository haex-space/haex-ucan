# Changelog

## 0.3.0 (2026-08-20)

### New API — role presets

The five-row role preset table now ships here instead of being hand-maintained
by each consumer. It was duplicated in three places (`CapabilitySet::role_preset`
in Rust, `capsFromSingle` in the vault frontend, and a third copy in the
fixture-vector generator, which existed only because this library exported
nothing to import). Two of those copies shipped the same bug — see the
invariant below.

- Type: `SpaceRole = 'reader' | 'writer' | 'inviter' | 'admin' | 'owner'`.
- Constant: `SPACE_ROLES` — all five roles in table order.
- Function: `spaceRolePreset(role): SpaceCapabilitySet`.

| role | `read` | `write` | `invite` | `admin` |
|---|---|---|---|---|
| `reader` | `false` | — | — | — |
| `writer` | `false` | `false` | — | — |
| `inviter` | **`true`** | — | `true` | — |
| `admin` | `true` | `true` | `true` | **`false`** |
| `owner` | `true` | `true` | `true` | `true` |

A `—` means the capability is not held at all; every other cell is that
entry's `delegatable` bit.

**The governing invariant: if a set contains `invite`, every other cap in that
set is `delegatable: true` — except `admin`.**

`enforceDelegatable` iterates `SPACE_CAP_ORDER` (`read`, `write`, `invite`,
`admin`) and returns on the *first* offender. An inviter whose own `read` were
`delegatable: false` therefore trips on `read` before `invite` is ever
considered: the invite capability is **inert** and its holder can delegate
nothing at all. That is the bug two of the three copies shipped.

`admin` is the deliberate exception — holding it non-delegatably is what
reserves minting further admins to the space root. Only the `owner` row carries
`admin: { delegatable: true }`.

The `reader` and `writer` rows deliberately keep `read` at
`delegatable: false` and must not be "fixed" for symmetry with the rows below
them: neither carries `invite`, so neither can reach a delegation boundary
where the bit would be read, and least privilege is the honest default there.

No union helper is exported. The presets are not nested, so a request naming
several capabilities cannot be served by OR-ing rows — `{write, invite}` would
yield `read(true) write(false) invite(true)`, whose holder can hand out a
reader but not a writer. Every TypeScript caller narrows to a single cap before
minting, so the merge case does not arise here; the Rust mirror has
`role_preset_union` because the P2P claim-invite path does read a
multi-capability list. A future caller needing one must re-apply the invariant
after merging, not merely OR the bits.

This table mirrors `CapabilitySet::role_preset` / `owner_root` in
`haex-vault/src-tauri/src/ucan/capability_set.rs`; the cross-language fixture
`haex-vault/src-tauri/tests/fixtures/ucan_chain_vectors.json` pins the two
against each other.

### POTENTIALLY BREAKING — `isSpaceCapValue` now validates entry shape

`isSpaceCapValue` was `Array.isArray(v)` and nothing more, while its signature
narrowed to `SpaceCapabilitySet`. `[{ junk: 1 }]` passed as a valid capability
set. It now additionally requires every element to be a non-null object whose
`cap` is in `SPACE_CAP_ORDER` and whose `delegatable` is a boolean.

```ts
isSpaceCapValue([{ junk: 1 }])                          // was true  → now false
isSpaceCapValue([{ cap: 'read' }])                      // was true  → now false
isSpaceCapValue([{ cap: 'superadmin', delegatable: 1 }]) // was true  → now false
isSpaceCapValue([])                                     // true (unchanged)
isSpaceCapValue([{ cap: 'read', delegatable: true }])    // true (unchanged)
```

Why it matters: a set with a missing `delegatable` used to reach
`holdsSpaceCap`, which answered `true` on presence alone. That failed closed in
practice (an `undefined` delegation bit is falsy), but consumers are starting to
persist and round-trip these sets, so the shape is now checked at the boundary.

Behaviour change to expect if you feed it malformed input: such a value is now
rejected *upstream* rather than being carried into `holdsSpaceCap` /
`enforceDelegatable`. Inside this library that tightens two paths in
`verifyDelegationChain` — the `server/relay` piggyback check
(`isSpaceCapValue(proofValue) && proofValue.length > 0`) and the general
per-resource attenuation branch. A child capability array carrying an unknown
cap now matches neither the space nor the server branch, so the chain walker
throws "not authorized to delegate" instead of silently accepting it: previously
`enforceDelegatable` never examined caps outside `SPACE_CAP_ORDER` and returned
`null` for such a child.

The guard validates entry *shape*, not the canonical-form invariants of
`SpaceCapabilitySet` (sorted, no duplicates). Route untrusted input through
`spaceCapabilitySetFromEntries` if you need those enforced too.

#### Consumer impact (audited before release)

All six call sites in `haex-vault` and `haex-sync-server` were reviewed. None
relies on the loose behaviour — every one either hard-rejects or fails closed on
`false`, and every producer in both repos already emits `{cap, delegatable}`
through the builder. Two things to know when bumping the dependency:

- Both repos pin `0.2.x` (`^0.2.0` does not cross a 0.x minor), so nothing picks
  this up until its manifest is bumped explicitly.
- `haex-vault`'s Rust `CapEntry` has `#[serde(default)]` on `delegatable`, so the
  Rust verifier accepts `[{"cap":"read"}]` where this check now rejects it. Worth
  closing in the same release if bit-for-bit parity matters, along with a negative
  fixture vector for that shape.

## 0.2.0 (2026-08-14)

### BREAKING CHANGES

- **Space capabilities in UCAN payloads are now orthogonal `SpaceCapabilitySet`
  arrays** (`[{cap, delegatable}, ...]`) instead of hierarchical strings
  (`"space/write"`). Wire form is bit-exactly compatible with the Rust side's
  `CapabilitySet` in `haex-vault/src-tauri/src/ucan/capability_set.rs` — both
  produce/consume the same canonical JSON.

- **Removed exports**:
  - Types: `SpaceCapability`, `Capability` (union type).
  - Values: `SPACE_CAPABILITY_LEVEL`, `satisfies`, `canDelegate`,
    `capabilitiesSatisfy`, `SpaceCapabilities` (const map).

- **Renamed**: `SpaceCapabilities` const map → `SpaceCaps`. Values are the new
  bare cap names (`'read' | 'write' | 'invite' | 'admin'`) instead of the
  prefixed `'space/*'` form.

- **Chain walker (`verifyDelegationChain`)** now enforces
  `enforceDelegatable(parent, child)` per hop instead of hierarchical
  `canDelegate`. A parent must both hold the cap AND have `delegatable: true`
  for the child to receive it.

- **`validateUcan` capability argument** is now
  `RequiredCapability = SpaceCap | ServerCapability` (single-cap for spaces;
  full-string for server delegations). Runtime discrimination via
  `isServerCapValue` from `./capabilities`.

- **`server/relay` semantics preserved verbatim**: any token that holds any
  space-cap in its parent chain still authorizes `server/relay` delegation.
  The check is now shape-based (`isSpaceCapValue(v) && v.length > 0`) rather
  than string-prefix-based.

### New API

- Types: `SpaceCap`, `CapEntry`, `SpaceCapabilitySet`, `SpaceCapabilitySetBuilder`,
  `DelegationError`, `DelegationErrorKind`, `ServerCap`, `CapabilityValue`,
  `RequiredCapability`.
- Constructors: `spaceCapabilitySet()` fluent builder, `spaceCapabilitySetFromEntries()`.
- Query: `holdsSpaceCap`, `isSpaceCapDelegatable`, `holdsServerCap`.
- Attenuation: `enforceDelegatable(parent, child): DelegationError | null`.
  Returns `null` on success; on failure returns the first-offender in
  `SPACE_CAP_ORDER` with `kind: 'missing' | 'not_delegatable'`.
- Discriminators: `isSpaceCapValue`, `isServerCapValue`.
- Constant: `SPACE_CAP_ORDER` (canonical wire ordering — do not reshuffle).

### Migration Guide

1. **Fixture / issuance sites**: replace `'space/write'` with
   `spaceCapabilitySet().write(true).build()`. The `true`/`false` argument
   controls `delegatable` — for leaf tokens with no downstream children,
   `false` is fine; for tokens that will delegate further, `true`.

2. **Satisfaction check** (e.g. server-side `requireCapability`):
   ```ts
   // Before
   if (!held || !satisfies(held, 'space/write')) reject()

   // After
   if (!isSpaceCapValue(held) || !holdsSpaceCap(held, 'write')) reject()
   ```

3. **Delegation attenuation** (chain-walker-adjacent code):
   ```ts
   // Before
   if (!canDelegate(parentCap, childCap)) reject()

   // After
   const err = enforceDelegatable(parentSet, childSet)
   if (err) reject(`${err.kind} for ${err.cap}`)
   ```

4. **Cap-name literals**: strip the `space/` prefix. `'space/read'` → `'read'`.
   `SpaceCapabilities.WRITE` → `SpaceCaps.WRITE` (value is `'write'` not
   `'space/write'`).

5. **Coordinated release**: `haex-vault` (Rust + TS) and `haex-sync-server`
   ship companion PRs adopting v0.2.0 together — see the plan at
   `docs/plans/2026-08-14-cap-set-v0.2.md` in this repo for context.

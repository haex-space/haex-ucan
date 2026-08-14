# Changelog

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

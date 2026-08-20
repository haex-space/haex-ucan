import type { ServerCapability } from './types'

/**
 * Orthogonal space capabilities.
 *
 * Wire-form must be bit-exactly compatible with the Rust side's
 * `CapabilitySet` at
 * `haex-vault/src-tauri/src/ucan/capability_set.rs`.
 * Rust uses `#[serde(rename_all = "snake_case")]` on `Cap`, so the
 * on-wire tokens are `"read" | "write" | "invite" | "admin"`.
 */
export type SpaceCap = 'read' | 'write' | 'invite' | 'admin'

/**
 * A single capability entry: which cap is held, and whether the holder
 * may delegate it further downstream.
 */
export interface CapEntry {
  cap: SpaceCap
  delegatable: boolean
}

/**
 * A set of orthogonal space capabilities.
 *
 * Invariants:
 *   - sorted by SPACE_CAP_ORDER
 *   - no duplicates
 *
 * Prefer building with {@link spaceCapabilitySet} or
 * {@link spaceCapabilitySetFromEntries} — both enforce the invariants.
 */
export type SpaceCapabilitySet = readonly CapEntry[]

/**
 * Canonical ordering for SpaceCap. Used for stable serialization and
 * for reporting the first-offender in {@link enforceDelegatable}.
 */
export const SPACE_CAP_ORDER: readonly SpaceCap[] = [
  'read',
  'write',
  'invite',
  'admin',
] as const

/**
 * Reasons a delegation attempt can fail against a parent set.
 */
export type DelegationErrorKind = 'missing' | 'not_delegatable'

/**
 * Structured delegation failure, tagged with the first-offending cap
 * in SPACE_CAP_ORDER.
 */
export interface DelegationError {
  kind: DelegationErrorKind
  cap: SpaceCap
}

/**
 * Build a SpaceCapabilitySet from raw entries.
 *
 * Sorts by SPACE_CAP_ORDER and rejects duplicates / unknown caps.
 */
export function spaceCapabilitySetFromEntries(
  entries: readonly CapEntry[],
): SpaceCapabilitySet {
  const seen = new Set<SpaceCap>()
  for (const e of entries) {
    if (!SPACE_CAP_ORDER.includes(e.cap)) throw new Error(`unknown cap: ${e.cap}`)
    if (seen.has(e.cap)) throw new Error(`duplicate cap: ${e.cap}`)
    seen.add(e.cap)
  }
  const capOrder = new Map(SPACE_CAP_ORDER.map((c, i) => [c, i]))
  return [...entries].sort((a, b) => capOrder.get(a.cap)! - capOrder.get(b.cap)!)
}

/**
 * Fluent builder for a SpaceCapabilitySet.
 *
 * Repeated calls to the same cap keep the last-written entry (map-based).
 * `build()` returns a sorted, duplicate-free set.
 */
export interface SpaceCapabilitySetBuilder {
  read(delegatable: boolean): SpaceCapabilitySetBuilder
  write(delegatable: boolean): SpaceCapabilitySetBuilder
  invite(delegatable: boolean): SpaceCapabilitySetBuilder
  admin(delegatable: boolean): SpaceCapabilitySetBuilder
  build(): SpaceCapabilitySet
}

/**
 * Create a fluent SpaceCapabilitySetBuilder.
 *
 * Example:
 *   const set = spaceCapabilitySet().read(true).write(false).build()
 */
export function spaceCapabilitySet(): SpaceCapabilitySetBuilder {
  const entries = new Map<SpaceCap, CapEntry>()
  const add = (cap: SpaceCap, delegatable: boolean) => {
    entries.set(cap, { cap, delegatable })
    return builder
  }
  const builder: SpaceCapabilitySetBuilder = {
    read: d => add('read', d),
    write: d => add('write', d),
    invite: d => add('invite', d),
    admin: d => add('admin', d),
    build: () => spaceCapabilitySetFromEntries([...entries.values()]),
  }
  return builder
}

/**
 * Member roles in the preset table below.
 *
 * A role is not a capability and carries no rank — it is a *name for one
 * row* of {@link spaceRolePreset}. There is no implication between roles
 * any more than there is between caps.
 */
export type SpaceRole = 'reader' | 'writer' | 'inviter' | 'admin' | 'owner'

/**
 * All roles, in the order of the {@link spaceRolePreset} table
 * (least to most privileged). Presentational only — nothing derives
 * authorization from this ordering.
 */
export const SPACE_ROLES: readonly SpaceRole[] = [
  'reader',
  'writer',
  'inviter',
  'admin',
  'owner',
] as const

/**
 * The capability set for a member role — the exact set every delegation
 * path hands out.
 *
 * | role      | `read`     | `write` | `invite` | `admin`     |
 * |-----------|------------|---------|----------|-------------|
 * | `reader`  | `false`    | —       | —        | —           |
 * | `writer`  | `false`    | `false` | —        | —           |
 * | `inviter` | **`true`** | —       | `true`   | —           |
 * | `admin`   | `true`     | `true`  | `true`   | **`false`** |
 * | `owner`   | `true`     | `true`  | `true`   | `true`      |
 *
 * A `—` means the capability is not held at all; every other cell is that
 * entry's `delegatable` bit.
 *
 * ## Invariant
 *
 * **If a set contains `invite`, every other cap in that set is
 * `delegatable: true` — except `admin`.**
 *
 * {@link enforceDelegatable} iterates {@link SPACE_CAP_ORDER} and returns
 * on the *first* offender. An inviter whose own `read` were
 * `delegatable: false` would therefore trip on `read` before `invite` is
 * ever considered: the invite capability would be **inert** and its holder
 * could delegate nothing at all. This exact bug shipped in all three
 * hand-maintained copies of this table and was found in review.
 *
 * `admin` is the deliberate exception. Holding it non-delegatably is what
 * reserves minting further admins to the space root — a delegated admin may
 * hand out reader/writer/inviter presets but can never create another
 * admin. Only the `owner` row carries `admin: { delegatable: true }`.
 *
 * The `reader` and `writer` rows deliberately keep `read` at
 * `delegatable: false`, and must NOT be "fixed" to `true` for symmetry with
 * the rows below them: neither preset carries `invite`, so neither can ever
 * reach a delegation boundary where the bit would be read, and least
 * privilege is the honest default there.
 *
 * "An admin has all rights" lives here — the `admin` role expands to all
 * four caps at mint time — and never in {@link holdsSpaceCap}, which stays
 * exact-match.
 *
 * ## Builder footgun
 *
 * The {@link SpaceCapabilitySetBuilder} boolean is `delegatable`, and
 * calling a method at all *grants* the cap. Withholding a cap means
 * omitting the call, not passing `false`:
 * `spaceCapabilitySet().write(false).build()` yields
 * `[{ cap: 'write', delegatable: false }]`, for which
 * `holdsSpaceCap(set, 'write')` is `true`.
 *
 * ## Mirror
 *
 * Mirrored in Rust as `CapabilitySet::role_preset` / `owner_root` in
 * `haex-vault/src-tauri/src/ucan/capability_set.rs` (keyed on `Cap`, with
 * the `owner` row split out into `owner_root`). The two tables MUST stay
 * identical: a token minted on one side is attenuation-checked on the
 * other, and the cross-language fixture
 * `haex-vault/src-tauri/tests/fixtures/ucan_chain_vectors.json` pins them
 * against each other.
 *
 * ## Multi-capability requests
 *
 * The presets are not nested — an `inviter` has no `write`, a `writer` has
 * no `invite` — so a request naming several capabilities cannot be served
 * by OR-ing the bits of several rows. `{ write, invite }` would yield
 * `read(true) write(false) invite(true)`, whose holder can hand out a
 * reader but not a writer: the invariant above has to be re-applied after
 * any merge. No TypeScript caller mints from a multi-capability list today
 * (they all narrow to one cap first), so this library exports no union
 * helper; the Rust mirror has `role_preset_union` because the P2P
 * claim-invite path does read such a list. A future caller that needs one
 * here must re-apply the invariant, not merely OR the bits.
 */
export function spaceRolePreset(role: SpaceRole): SpaceCapabilitySet {
  switch (role) {
    case 'reader':
      return spaceCapabilitySet().read(false).build()
    case 'writer':
      return spaceCapabilitySet().read(false).write(false).build()
    case 'inviter':
      return spaceCapabilitySet().read(true).invite(true).build()
    case 'admin':
      return spaceCapabilitySet()
        .read(true)
        .write(true)
        .invite(true)
        .admin(false)
        .build()
    case 'owner':
      return spaceCapabilitySet()
        .read(true)
        .write(true)
        .invite(true)
        .admin(true)
        .build()
  }
}

/**
 * True iff `set` contains an entry for `cap`.
 *
 * Note: the model is orthogonal — holding `admin` does NOT imply
 * holding `read`. Callers who want the old hierarchical semantics
 * must add the caps explicitly.
 */
export function holdsSpaceCap(set: SpaceCapabilitySet, cap: SpaceCap): boolean {
  return set.some(e => e.cap === cap)
}

/**
 * True iff `set` contains `cap` AND that entry is marked delegatable.
 */
export function isSpaceCapDelegatable(set: SpaceCapabilitySet, cap: SpaceCap): boolean {
  return set.some(e => e.cap === cap && e.delegatable)
}

/**
 * Verify that a child delegation is authorized by a parent set.
 *
 * Rules:
 *   - Every cap in `child` must be present in `parent`.
 *   - The parent entry for that cap must be `delegatable: true`.
 *
 * On failure returns the first-offender in SPACE_CAP_ORDER; on success
 * returns `null`.
 */
export function enforceDelegatable(
  parent: SpaceCapabilitySet,
  child: SpaceCapabilitySet,
): DelegationError | null {
  const parentByCap = new Map(parent.map(e => [e.cap, e]))
  for (const cap of SPACE_CAP_ORDER) {
    const childEntry = child.find(e => e.cap === cap)
    if (!childEntry) continue
    const parentEntry = parentByCap.get(cap)
    if (!parentEntry) return { kind: 'missing', cap }
    if (!parentEntry.delegatable) return { kind: 'not_delegatable', cap }
  }
  return null
}

/**
 * Runtime discriminator: a SpaceCap value is an array of well-formed
 * {@link CapEntry} objects — every element has a `cap` in
 * {@link SPACE_CAP_ORDER} and a boolean `delegatable`.
 *
 * This is the wire/storage boundary guard. It validates entry *shape*, not
 * the canonical-form invariants of {@link SpaceCapabilitySet} (sorted, no
 * duplicates) — route untrusted input through
 * {@link spaceCapabilitySetFromEntries} if you need those too.
 *
 * An empty array is a valid (empty) set: it holds no cap, so every
 * {@link holdsSpaceCap} query fails closed.
 */
export function isSpaceCapValue(v: unknown): v is SpaceCapabilitySet {
  return Array.isArray(v) && v.every(
    e => e !== null
      && typeof e === 'object'
      && SPACE_CAP_ORDER.includes((e as CapEntry).cap)
      && typeof (e as CapEntry).delegatable === 'boolean',
  )
}

/**
 * Runtime discriminator: a ServerCap value is a string of the form
 * `server/<name>` (currently only `server/relay`).
 */
export function isServerCapValue(v: unknown): v is ServerCapability {
  return typeof v === 'string' && v.startsWith('server/')
}

/**
 * Suffix of a ServerCapability — e.g. `'relay'` for `'server/relay'`.
 */
export type ServerCap = 'relay'

/**
 * True iff `held` is exactly `server/${cap}`.
 */
export function holdsServerCap(held: ServerCapability, cap: ServerCap): boolean {
  return held === `server/${cap}`
}

/**
 * Extract the space ID from a resource identifier.
 * Resource format: "space:<space-id>"
 */
export function parseSpaceResource(resource: string): string | null {
  if (!resource.startsWith('space:')) return null
  return resource.slice('space:'.length)
}

/**
 * Create a resource identifier for a space.
 */
export function spaceResource(spaceId: string): string {
  return `space:${spaceId}`
}

/**
 * Create a resource identifier for a server delegation.
 */
export function serverResource(serverDid: string): string {
  return `server:${serverDid}`
}

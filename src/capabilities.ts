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
 * Runtime discriminator: a SpaceCap value is an array (of CapEntry).
 *
 * Task 3 will refine the return type to the concrete CapabilityValue
 * union; the runtime check stays identical.
 */
export function isSpaceCapValue(v: unknown): v is SpaceCapabilitySet {
  return Array.isArray(v)
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

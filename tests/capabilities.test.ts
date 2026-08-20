import { describe, it, expect } from 'vitest'
import {
  type SpaceCap,
  type CapEntry,
  type SpaceCapabilitySet,
  type SpaceRole,
  type DelegationError,
  spaceCapabilitySetFromEntries,
  spaceCapabilitySet,
  spaceRolePreset,
  holdsSpaceCap,
  isSpaceCapDelegatable,
  enforceDelegatable,
  isSpaceCapValue,
  isServerCapValue,
  SPACE_CAP_ORDER,
  SPACE_ROLES,
} from '../src/capabilities'

describe('SpaceCapabilitySet — construction', () => {
  it('spaceCapabilitySetFromEntries sorts by SPACE_CAP_ORDER', () => {
    const set = spaceCapabilitySetFromEntries([
      { cap: 'admin', delegatable: true },
      { cap: 'read', delegatable: false },
    ])
    expect(set.map(e => e.cap)).toEqual(['read', 'admin'])
  })

  it('spaceCapabilitySetFromEntries rejects duplicates', () => {
    expect(() => spaceCapabilitySetFromEntries([
      { cap: 'write', delegatable: true },
      { cap: 'write', delegatable: false },
    ])).toThrow(/duplicate/)
  })

  it('spaceCapabilitySet builder produces sorted output', () => {
    const set = spaceCapabilitySet().admin(true).read(false).build()
    expect(set.map(e => e.cap)).toEqual(['read', 'admin'])
  })
})

describe('SpaceCapabilitySet — query', () => {
  it('holdsSpaceCap returns true for held', () => {
    const set = spaceCapabilitySet().write(true).build()
    expect(holdsSpaceCap(set, 'write')).toBe(true)
  })

  it('holdsSpaceCap returns false for non-held (no hierarchy)', () => {
    const set = spaceCapabilitySet().admin(true).build()
    // Kritisch: Admin holds Admin, but does NOT satisfy Read in the orthogonal model.
    expect(holdsSpaceCap(set, 'read')).toBe(false)
  })

  it('isSpaceCapDelegatable requires the flag', () => {
    const set = spaceCapabilitySet().write(false).build()
    expect(holdsSpaceCap(set, 'write')).toBe(true)
    expect(isSpaceCapDelegatable(set, 'write')).toBe(false)
  })
})

describe('SpaceCapabilitySet — attenuation', () => {
  it('enforceDelegatable ok when child ⊆ parent (all delegatable)', () => {
    const parent = spaceCapabilitySet().read(true).write(true).build()
    const child = spaceCapabilitySet().read(true).build()
    expect(enforceDelegatable(parent, child)).toBeNull()
  })

  it('enforceDelegatable returns missing when parent lacks cap', () => {
    const parent = spaceCapabilitySet().write(true).build()
    const child = spaceCapabilitySet().read(true).build()
    const err = enforceDelegatable(parent, child)
    expect(err).toEqual<DelegationError>({ kind: 'missing', cap: 'read' })
  })

  it('enforceDelegatable returns not_delegatable when parent has non-delegatable', () => {
    const parent = spaceCapabilitySet().write(false).build()
    const child = spaceCapabilitySet().write(true).build()
    const err = enforceDelegatable(parent, child)
    expect(err).toEqual<DelegationError>({ kind: 'not_delegatable', cap: 'write' })
  })

  it('enforceDelegatable reports first-offender in SPACE_CAP_ORDER', () => {
    const parent = spaceCapabilitySet().build()
    const child = spaceCapabilitySet().read(true).write(true).build()
    // Both Read + Write are missing; must report Read (first in order)
    const err = enforceDelegatable(parent, child)
    expect(err).toEqual<DelegationError>({ kind: 'missing', cap: 'read' })
  })
})

describe('CapabilityValue discrimination', () => {
  it('isSpaceCapValue for arrays', () => {
    const set = spaceCapabilitySet().read(true).build()
    expect(isSpaceCapValue(set)).toBe(true)
    expect(isServerCapValue(set)).toBe(false)
  })

  it('isServerCapValue for server strings', () => {
    expect(isServerCapValue('server/relay')).toBe(true)
    expect(isSpaceCapValue('server/relay')).toBe(false)
  })
})

describe('isSpaceCapValue — entry-shape validation', () => {
  it('accepts the empty set', () => {
    // An empty set holds no cap, so every holdsSpaceCap query fails closed.
    expect(isSpaceCapValue([])).toBe(true)
  })

  it('accepts a well-formed set', () => {
    expect(isSpaceCapValue([
      { cap: 'read', delegatable: true },
      { cap: 'admin', delegatable: false },
    ])).toBe(true)
  })

  it('rejects entries that are not CapEntry-shaped at all', () => {
    expect(isSpaceCapValue([{ junk: 1 }])).toBe(false)
  })

  it('rejects an entry missing `delegatable`', () => {
    // Before hardening this passed, and holdsSpaceCap([{cap:'read'}], 'read')
    // answered `true` on a set whose delegation bit was undefined.
    expect(isSpaceCapValue([{ cap: 'read' }])).toBe(false)
  })

  it('rejects a non-boolean `delegatable`', () => {
    expect(isSpaceCapValue([{ cap: 'read', delegatable: 'yes' }])).toBe(false)
  })

  it('rejects a cap outside SPACE_CAP_ORDER', () => {
    // enforceDelegatable only iterates SPACE_CAP_ORDER, so an entry like this
    // is invisible to attenuation. Rejecting it here is what keeps it from
    // ever reaching that code.
    expect(isSpaceCapValue([{ cap: 'superadmin', delegatable: true }])).toBe(false)
  })

  it('rejects null and primitive entries', () => {
    expect(isSpaceCapValue([null])).toBe(false)
    expect(isSpaceCapValue(['read'])).toBe(false)
    expect(isSpaceCapValue([1])).toBe(false)
  })

  it('rejects a set where only one entry is malformed', () => {
    expect(isSpaceCapValue([
      { cap: 'read', delegatable: true },
      { cap: 'write' },
    ])).toBe(false)
  })

  it('rejects non-arrays', () => {
    expect(isSpaceCapValue(null)).toBe(false)
    expect(isSpaceCapValue(undefined)).toBe(false)
    expect(isSpaceCapValue({ cap: 'read', delegatable: true })).toBe(false)
  })

  it('validates entry shape only — not sort order or duplicates', () => {
    // Documented scope: this is a boundary shape guard, not a canonicaliser.
    // Callers needing the sorted/duplicate-free invariant must route through
    // spaceCapabilitySetFromEntries.
    expect(isSpaceCapValue([
      { cap: 'admin', delegatable: false },
      { cap: 'read', delegatable: true },
      { cap: 'read', delegatable: false },
    ])).toBe(true)
  })
})

describe('spaceRolePreset — the preset table', () => {
  it('SPACE_ROLES lists the five rows in table order', () => {
    expect(SPACE_ROLES).toEqual(['reader', 'writer', 'inviter', 'admin', 'owner'])
  })

  it('reader', () => {
    expect(spaceRolePreset('reader')).toEqual<CapEntry[]>([
      { cap: 'read', delegatable: false },
    ])
  })

  it('writer', () => {
    expect(spaceRolePreset('writer')).toEqual<CapEntry[]>([
      { cap: 'read', delegatable: false },
      { cap: 'write', delegatable: false },
    ])
  })

  it('inviter', () => {
    // read is delegatable:true — see the invariant. A non-delegatable read
    // here would make the invite cap inert.
    expect(spaceRolePreset('inviter')).toEqual<CapEntry[]>([
      { cap: 'read', delegatable: true },
      { cap: 'invite', delegatable: true },
    ])
  })

  it('admin', () => {
    // admin is delegatable:false — only the space root mints admins.
    expect(spaceRolePreset('admin')).toEqual<CapEntry[]>([
      { cap: 'read', delegatable: true },
      { cap: 'write', delegatable: true },
      { cap: 'invite', delegatable: true },
      { cap: 'admin', delegatable: false },
    ])
  })

  it('owner', () => {
    // The only row with admin delegatable — the space root.
    expect(spaceRolePreset('owner')).toEqual<CapEntry[]>([
      { cap: 'read', delegatable: true },
      { cap: 'write', delegatable: true },
      { cap: 'invite', delegatable: true },
      { cap: 'admin', delegatable: true },
    ])
  })

  it('every preset is in SPACE_CAP_ORDER with no duplicates', () => {
    const rank = new Map(SPACE_CAP_ORDER.map((c, i) => [c, i]))
    for (const role of SPACE_ROLES) {
      const caps = spaceRolePreset(role).map(e => e.cap)
      expect(caps).toEqual([...caps].sort((a, b) => rank.get(a)! - rank.get(b)!))
      expect(new Set(caps).size).toBe(caps.length)
    }
  })
})

describe('spaceRolePreset — the governing invariant', () => {
  it('a set holding invite has every other cap delegatable, except admin', () => {
    // Property over all five rows: if `invite` is present, any cap other than
    // `admin` whose delegatable bit were false would be reported by
    // enforceDelegatable first and render the invite inert.
    let rowsHoldingInvite = 0
    for (const role of SPACE_ROLES) {
      const set = spaceRolePreset(role)
      if (!holdsSpaceCap(set, 'invite')) continue
      rowsHoldingInvite += 1
      for (const entry of set) {
        if (entry.cap === 'admin') continue
        expect(
          entry.delegatable,
          `role "${role}" holds invite but ${entry.cap} is not delegatable`,
        ).toBe(true)
      }
    }
    // Guard against a vacuous property: inviter, admin and owner hold invite.
    expect(rowsHoldingInvite).toBe(3)
  })

  it('only owner may delegate admin', () => {
    for (const role of SPACE_ROLES) {
      expect(
        isSpaceCapDelegatable(spaceRolePreset(role), 'admin'),
        `role "${role}"`,
      ).toBe(role === 'owner')
    }
  })
})

describe('spaceRolePreset — delegation behaviour', () => {
  const delegate = (parent: SpaceRole, child: SpaceRole): DelegationError | null =>
    enforceDelegatable(spaceRolePreset(parent), spaceRolePreset(child))

  it('inviter can delegate reader', () => {
    // The regression that shipped in all three copies: with read(false) on the
    // inviter this was {kind:'not_delegatable', cap:'read'} and the inviter
    // could grant nothing at all.
    expect(delegate('inviter', 'reader')).toBeNull()
  })

  it('inviter cannot delegate writer — it holds no write', () => {
    expect(delegate('inviter', 'writer')).toEqual<DelegationError>({
      kind: 'missing',
      cap: 'write',
    })
  })

  it('inviter cannot delegate inviter, admin or owner', () => {
    // An inviter holds invite delegatably, so it may hand out read+invite…
    expect(delegate('inviter', 'inviter')).toBeNull()
    // …but not write or admin.
    expect(delegate('inviter', 'admin')).toEqual<DelegationError>({
      kind: 'missing',
      cap: 'write',
    })
    expect(delegate('inviter', 'owner')).toEqual<DelegationError>({
      kind: 'missing',
      cap: 'write',
    })
  })

  it('admin can delegate reader, writer and inviter', () => {
    expect(delegate('admin', 'reader')).toBeNull()
    expect(delegate('admin', 'writer')).toBeNull()
    expect(delegate('admin', 'inviter')).toBeNull()
  })

  it('admin cannot delegate admin — no admin proliferation', () => {
    expect(delegate('admin', 'admin')).toEqual<DelegationError>({
      kind: 'not_delegatable',
      cap: 'admin',
    })
  })

  it('owner can delegate every role', () => {
    for (const role of SPACE_ROLES) {
      expect(delegate('owner', role), `owner → ${role}`).toBeNull()
    }
  })

  it('reader can delegate nothing', () => {
    for (const role of SPACE_ROLES) {
      expect(delegate('reader', role), `reader → ${role}`).not.toBeNull()
    }
    // Not even its own row: read is held, but terminally.
    expect(delegate('reader', 'reader')).toEqual<DelegationError>({
      kind: 'not_delegatable',
      cap: 'read',
    })
  })

  it('writer can delegate nothing', () => {
    for (const role of SPACE_ROLES) {
      expect(delegate('writer', role), `writer → ${role}`).not.toBeNull()
    }
    expect(delegate('writer', 'writer')).toEqual<DelegationError>({
      kind: 'not_delegatable',
      cap: 'read',
    })
  })

  it('every preset is a valid space-cap value at the wire boundary', () => {
    for (const role of SPACE_ROLES) {
      expect(isSpaceCapValue(spaceRolePreset(role)), `role "${role}"`).toBe(true)
    }
  })
})

describe('SpaceCapabilitySet — regression against hierarchical world', () => {
  it('Admin does NOT hold Read', () => {
    // In the old hierarchical model, admin was strictly stronger than read,
    // so satisfies(admin, read) was true. In the orthogonal model, admin
    // only satisfies admin. This test locks that in.
    const set = spaceCapabilitySet().admin(true).build()
    expect(holdsSpaceCap(set, 'read')).toBe(false)
    expect(holdsSpaceCap(set, 'admin')).toBe(true)
  })

  it('Write-only leaf does NOT satisfy Read-required floor', () => {
    // Contract regression: consumers using holdsSpaceCap as the "does this token
    // grant the operation?" gate must not silently authorize Read when only
    // Write is held. In the hierarchical world, write > read implied yes;
    // in the orthogonal world, only explicit Read grants Read.
    const set = spaceCapabilitySet().write(true).build()
    expect(holdsSpaceCap(set, 'read')).toBe(false)
  })

  it('non-delegatable Write parent → Write child is rejected', () => {
    // Attenuation regression: a parent that holds Write with delegatable=false
    // may exercise Write themselves but not delegate it. A child that claims
    // Write from such a parent must be rejected as not_delegatable, not missing.
    const parent = spaceCapabilitySet().write(false).build()
    const child = spaceCapabilitySet().write(true).build()
    expect(enforceDelegatable(parent, child)).toEqual({
      kind: 'not_delegatable',
      cap: 'write',
    })
  })

  it('multi-cap root with delegatable Read+Write+Invite+Admin delegates any subset', () => {
    // Positive coverage: a full-power delegatable root can attenuate to any
    // combination of caps the child chooses. This is the shape of the space
    // owner's self-signed root token.
    const root = spaceCapabilitySet().read(true).write(true).invite(true).admin(true).build()
    const child = spaceCapabilitySet().read(true).invite(true).build()
    expect(enforceDelegatable(root, child)).toBeNull()
  })

  it('missing cap outranks non-delegatable in SPACE_CAP_ORDER report', () => {
    // First-offender rule: enforceDelegatable reports the first FAILING cap
    // in SPACE_CAP_ORDER order, not the "worst" failure kind. If Read is
    // missing and Write is not_delegatable, the report must be Read/missing
    // (Read comes first in SPACE_CAP_ORDER).
    const parent = spaceCapabilitySet().write(false).build()
    const child = spaceCapabilitySet().read(true).write(true).build()
    expect(enforceDelegatable(parent, child)).toEqual({
      kind: 'missing',
      cap: 'read',
    })
  })

  it('SPACE_CAP_ORDER is the canonical ordering (guard against reshuffle)', () => {
    // Wire-compatibility regression: the sort order used for canonical
    // serialization matches Rust's Cap discriminant order in
    // haex-vault/src-tauri/src/ucan/capability_set.rs. Reshuffling this array
    // breaks bit-exact wire compatibility with the Rust side.
    expect(SPACE_CAP_ORDER).toEqual(['read', 'write', 'invite', 'admin'])
  })
})

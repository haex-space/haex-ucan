import { describe, it, expect } from 'vitest'
import {
  type SpaceCap,
  type CapEntry,
  type SpaceCapabilitySet,
  type DelegationError,
  spaceCapabilitySetFromEntries,
  spaceCapabilitySet,
  holdsSpaceCap,
  isSpaceCapDelegatable,
  enforceDelegatable,
  isSpaceCapValue,
  isServerCapValue,
  SPACE_CAP_ORDER,
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

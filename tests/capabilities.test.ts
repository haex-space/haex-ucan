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

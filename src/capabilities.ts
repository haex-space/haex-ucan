import type { Capability, SpaceCapability, Capabilities } from './types'

/**
 * Privilege level for each space capability (higher = more privileged)
 */
const SPACE_CAPABILITY_LEVEL: Record<SpaceCapability, number> = {
  'space/admin': 4,
  'space/invite': 3,
  'space/write': 2,
  'space/read': 1,
}

/**
 * Check if a capability satisfies a required capability level.
 * A higher-level capability always satisfies a lower-level requirement.
 *
 * Example: space/admin satisfies space/write, but not vice versa.
 */
export function satisfies(held: Capability, required: Capability): boolean {
  if (held === required) return true

  // server/relay only satisfies itself
  if (held === 'server/relay' || required === 'server/relay') return false

  const heldLevel = SPACE_CAPABILITY_LEVEL[held as SpaceCapability]
  const requiredLevel = SPACE_CAPABILITY_LEVEL[required as SpaceCapability]

  if (heldLevel === undefined || requiredLevel === undefined) return false

  return heldLevel >= requiredLevel
}

/**
 * Check if a delegator can delegate a specific capability.
 * Attenuation: you can only delegate capabilities at your level or below.
 *
 * This is equivalent to `satisfies` — if you hold a capability,
 * you can delegate anything it satisfies.
 */
export function canDelegate(delegatorCapability: Capability, delegatedCapability: Capability): boolean {
  return satisfies(delegatorCapability, delegatedCapability)
}

/**
 * Check if a set of capabilities satisfies a required capability for a resource.
 * Looks up the resource in the capabilities map and checks the level.
 */
export function capabilitiesSatisfy(
  capabilities: Capabilities,
  resource: string,
  required: Capability,
): boolean {
  const held = capabilities[resource]
  if (!held) return false
  return satisfies(held, required)
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

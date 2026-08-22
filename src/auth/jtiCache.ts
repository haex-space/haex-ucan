/**
 * In-process cache of seen PoP `jti` values.
 *
 * Server-side replay defence for the PoP window: the verifier calls
 * `has(jti)` to reject a seen value and `add(jti, expiresAt)` after a
 * successful verify. Each entry carries its own absolute expiration, so a
 * future-dated proof (accepted under `clockSkewMs`) is retained until *its*
 * `payload.exp` — not evicted early by a cache-wide TTL.
 *
 * Not shared across processes — multi-instance deploys either accept the
 * per-instance replay window (at most one PoP lifetime of duplicates against a
 * given instance) or reach for a shared store. The plan (§B.1) chose the
 * local map.
 */
export interface JtiCache {
  has(jti: string): boolean
  /**
   * Record `jti` as seen. `expiresAt` is the absolute ms epoch after which
   * the entry may be evicted — pass `payload.exp` so retention matches the
   * accepted proof's own validity window.
   */
  add(jti: string, expiresAt: number): void
  size(): number
  /** Stops the periodic sweep. Idempotent. */
  destroy(): void
}

export interface JtiCacheOptions {
  /**
   * How often to sweep expired entries. Defaults to 30_000 ms. Smaller values
   * bound memory more tightly at the cost of more scheduler wakeups. Lazy
   * eviction on `has()` catches expired entries between sweeps.
   */
  sweepIntervalMs?: number
}

/**
 * Create a jti cache. Call `destroy()` when done to release the sweep interval.
 */
export function createJtiTtlCache(opts: JtiCacheOptions = {}): JtiCache {
  const seen = new Map<string, number>()
  const sweepIntervalMs = opts.sweepIntervalMs ?? 30_000

  const timer: ReturnType<typeof setInterval> = setInterval(() => {
    const now = Date.now()
    for (const [jti, expiresAt] of seen) {
      if (expiresAt <= now) seen.delete(jti)
    }
  }, sweepIntervalMs)

  // Node/Bun `Timer` supports `unref()` to avoid keeping the event loop alive.
  // In DOM the returned handle is a plain number and has no `unref`.
  const unrefable = timer as unknown as { unref?: () => void }
  if (typeof unrefable.unref === 'function') unrefable.unref()

  let destroyed = false
  return {
    has: (jti) => {
      const expiresAt = seen.get(jti)
      if (expiresAt === undefined) return false
      if (expiresAt <= Date.now()) {
        seen.delete(jti)
        return false
      }
      return true
    },
    add: (jti, expiresAt) => {
      seen.set(jti, expiresAt)
    },
    size: () => seen.size,
    destroy: () => {
      if (destroyed) return
      destroyed = true
      clearInterval(timer)
      seen.clear()
    },
  }
}

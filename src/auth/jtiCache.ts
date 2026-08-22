/**
 * In-process TTL cache of seen PoP `jti` values.
 *
 * Server-side replay defence for the 60-s PoP window: the verifier calls
 * `has(jti)` to reject a seen value and `add(jti)` after a successful verify.
 *
 * Not shared across processes — multi-instance deploys either accept the
 * per-instance replay window (small: at most 60 s of duplicates against a given
 * instance) or reach for a shared store. The plan (§B.1) chose the local map.
 */
export interface JtiCache {
  has(jti: string): boolean
  add(jti: string): void
  size(): number
  /** Stops the periodic sweep. Idempotent. */
  destroy(): void
}

export interface JtiCacheOptions {
  /**
   * How long a `jti` stays in the cache. Should be `windowMs + max_clock_skew`
   * so an in-window replay is always caught (plan §B.1 uses 60_000 + 30_000).
   */
  ttlMs: number
  /**
   * How often to sweep expired entries. Defaults to `ttlMs / 2`. Smaller values
   * bound memory more tightly at the cost of more scheduler wakeups.
   */
  sweepIntervalMs?: number
}

/**
 * Create a jti cache. Call `destroy()` when done to release the sweep interval.
 */
export function createJtiTtlCache(opts: JtiCacheOptions): JtiCache {
  const seen = new Map<string, number>()
  const sweepIntervalMs = opts.sweepIntervalMs ?? Math.max(Math.floor(opts.ttlMs / 2), 1000)

  const timer: ReturnType<typeof setInterval> = setInterval(() => {
    const cutoff = Date.now() - opts.ttlMs
    for (const [jti, insertedAt] of seen) {
      if (insertedAt < cutoff) seen.delete(jti)
    }
  }, sweepIntervalMs)

  // Node/Bun `Timer` supports `unref()` to avoid keeping the event loop alive.
  // In DOM the returned handle is a plain number and has no `unref`.
  const unrefable = timer as unknown as { unref?: () => void }
  if (typeof unrefable.unref === 'function') unrefable.unref()

  let destroyed = false
  return {
    has: (jti) => seen.has(jti),
    add: (jti) => {
      seen.set(jti, Date.now())
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

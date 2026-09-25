/** Deterministic PRNG so the synthetic tenant is identical on every load. */
export class Rng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0 || 1;
  }

  /** mulberry32 */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  int(minInclusive: number, maxInclusive: number): number {
    return minInclusive + Math.floor(this.next() * (maxInclusive - minInclusive + 1));
  }

  float(min: number, max: number, decimals = 2): number {
    const value = min + this.next() * (max - min);
    return Number(value.toFixed(decimals));
  }

  bool(probabilityTrue: number): boolean {
    return this.next() < probabilityTrue;
  }

  pick<T>(items: readonly T[]): T {
    return items[Math.floor(this.next() * items.length)];
  }

  /** Picks from weighted entries of [value, weight]. */
  weighted<T>(entries: readonly (readonly [T, number])[]): T {
    const total = entries.reduce((sum, [, weight]) => sum + weight, 0);
    let roll = this.next() * total;
    for (const [value, weight] of entries) {
      roll -= weight;
      if (roll <= 0) return value;
    }
    return entries[entries.length - 1][0];
  }

  sample<T>(items: readonly T[], count: number): T[] {
    const pool = [...items];
    const taken: T[] = [];
    const n = Math.min(count, pool.length);
    for (let i = 0; i < n; i += 1) {
      taken.push(pool.splice(Math.floor(this.next() * pool.length), 1)[0]);
    }
    return taken;
  }

  /** ISO timestamp between `minDaysAgo` and `maxDaysAgo` relative to `now`. */
  dateDaysAgo(now: Date, maxDaysAgo: number, minDaysAgo = 0): string {
    const days = minDaysAgo + this.next() * (maxDaysAgo - minDaysAgo);
    return new Date(now.getTime() - days * 86_400_000).toISOString();
  }

  dateDaysAhead(now: Date, maxDaysAhead: number, minDaysAhead = 0): string {
    const days = minDaysAhead + this.next() * (maxDaysAhead - minDaysAhead);
    return new Date(now.getTime() + days * 86_400_000).toISOString();
  }
}

export const id = (prefix: string, n: number) => `${prefix}-${String(n).padStart(5, '0')}`;

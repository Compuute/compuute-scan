const hits = new Map<string, number[]>();

const WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_REQUESTS = 10;

export function checkRateLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const timestamps = hits.get(ip) ?? [];

  // Remove expired entries
  const valid = timestamps.filter((t) => now - t < WINDOW_MS);

  if (valid.length >= MAX_REQUESTS) {
    hits.set(ip, valid);
    return { allowed: false, remaining: 0 };
  }

  valid.push(now);
  hits.set(ip, valid);
  return { allowed: true, remaining: MAX_REQUESTS - valid.length };
}

import { NextRequest, NextResponse } from 'next/server';
import { runScan, validateRepoUrl } from '@/lib/scanner';
import { checkRateLimit } from '@/lib/rate-limit';

export const maxDuration = 60;

export async function POST(req: NextRequest) {
  // Rate limit by IP — prefer req.ip (set by Vercel/platform from real connection)
  const ip =
    req.ip ??
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    req.headers.get('x-real-ip') ??
    'unknown';

  const { allowed, remaining } = checkRateLimit(ip);
  if (!allowed) {
    return NextResponse.json(
      { error: 'Rate limit exceeded. Maximum 10 scans per hour.' },
      {
        status: 429,
        headers: { 'X-RateLimit-Remaining': '0' },
      },
    );
  }

  // Parse body
  let body: { repoUrl?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const { repoUrl } = body;
  if (!repoUrl || typeof repoUrl !== 'string' || repoUrl.length > 200) {
    return NextResponse.json({ error: 'Missing or invalid repoUrl field.' }, { status: 400 });
  }

  // Validate URL
  if (!validateRepoUrl(repoUrl)) {
    return NextResponse.json(
      { error: 'Invalid URL. Only public GitHub, GitLab, and Bitbucket repository URLs are accepted.' },
      { status: 400 },
    );
  }

  // Run scan
  try {
    const result = await runScan(repoUrl);
    return NextResponse.json(result, {
      headers: { 'X-RateLimit-Remaining': remaining.toString() },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed.';

    if (message.includes('too large')) {
      return NextResponse.json({ error: message }, { status: 413 });
    }

    console.error('Scan error:', message);
    return NextResponse.json(
      { error: 'Scan failed. The repository may be private, empty, or too large.' },
      { status: 500 },
    );
  }
}

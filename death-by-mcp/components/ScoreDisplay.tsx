'use client';

import { useEffect, useState } from 'react';
import { getRiskLabel } from '@/lib/scoring';
import type { ScanResult } from '@/lib/scoring';

export default function ScoreDisplay({ result }: { result: ScanResult }) {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    // Animate score counting up
    const target = result.score;
    if (target === 0) {
      setDisplayScore(0);
      return;
    }

    const duration = 1500;
    const steps = 60;
    const increment = target / steps;
    let current = 0;
    let step = 0;

    const timer = setInterval(() => {
      step++;
      current = Math.min(target, Math.round(increment * step));
      setDisplayScore(current);
      if (step >= steps) clearInterval(timer);
    }, duration / steps);

    return () => clearInterval(timer);
  }, [result.score]);

  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (result.score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-6">
      {/* Score ring */}
      <div className="relative">
        <svg width="160" height="160" className="animate-score-up">
          <circle
            cx="80"
            cy="80"
            r="45"
            fill="none"
            stroke="#1e1e2e"
            strokeWidth="8"
          />
          <circle
            cx="80"
            cy="80"
            r="45"
            fill="none"
            stroke={result.riskColor}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="score-ring"
            transform="rotate(-90 80 80)"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-4xl font-bold tabular-nums"
            style={{ color: result.riskColor }}
          >
            {displayScore}
          </span>
          <span className="text-xs text-slate-500">/100</span>
        </div>
      </div>

      {/* Risk badge */}
      <div
        className="rounded-full px-4 py-1.5 text-sm font-semibold"
        style={{
          backgroundColor: result.riskColor + '15',
          color: result.riskColor,
          border: `1px solid ${result.riskColor}30`,
        }}
      >
        {getRiskLabel(result.riskLevel)}
      </div>
    </div>
  );
}

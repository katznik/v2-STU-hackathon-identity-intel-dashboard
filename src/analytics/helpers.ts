import type { TenantDataset, User } from '../domain/types';

export const NOW = new Date('2026-09-25T00:00:00.000Z');

export function daysSince(iso: string | null): number {
  if (!iso) return Number.POSITIVE_INFINITY;
  return (NOW.getTime() - new Date(iso).getTime()) / 86_400_000;
}

export function daysUntil(iso: string): number {
  return (new Date(iso).getTime() - NOW.getTime()) / 86_400_000;
}

export function pct(part: number, total: number): number {
  if (!total) return 0;
  return Number(((part / total) * 100).toFixed(1));
}

export function isDormant(user: User, thresholdDays = 90): boolean {
  return user.accountEnabled && daysSince(user.lastSignInDateTime) > thresholdDays;
}

/** Principals holding any directory role, resolved through group assignments too. */
export function resolvePrivilegedUserIds(data: TenantDataset): Set<string> {
  const groupById = new Map(data.groups.map((g) => [g.id, g]));
  const ids = new Set<string>();
  for (const assignment of data.roleAssignments) {
    if (assignment.principalType === 'user') {
      ids.add(assignment.principalId);
    } else if (assignment.principalType === 'group') {
      for (const memberId of groupById.get(assignment.principalId)?.memberIds ?? []) ids.add(memberId);
    }
  }
  return ids;
}

export function roleTierOf(data: TenantDataset, roleId: string) {
  return data.roles.find((r) => r.id === roleId)?.tier ?? 'tier-2';
}

export function roleNameOf(data: TenantDataset, roleId: string) {
  return data.roles.find((r) => r.id === roleId)?.displayName ?? roleId;
}

/** Produces a descending-noise trend series ending at `current`. */
export function trendTo(current: number, seed: number, points = 12, drift = 1.4): number[] {
  const series: number[] = [];
  let value = current + drift * points * 0.55;
  for (let i = 0; i < points; i += 1) {
    const wobble = ((Math.sin(seed + i * 1.7) + Math.cos(seed * 0.7 + i)) / 2) * Math.max(1, current * 0.05);
    series.push(Math.max(0, Number((value + wobble).toFixed(1))));
    value -= drift;
  }
  series[points - 1] = current;
  return series;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat('en-US').format(Math.round(value));
}

export function formatCurrency(value: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  }).format(value);
}

export function formatDate(iso: string | null): string {
  if (!iso) return 'Never';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function gradeFor(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

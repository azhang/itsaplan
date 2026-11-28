import type { SQLWrapper } from 'drizzle-orm';
import { repositoryHosts } from '#modules/git/issue-sync';

// The issues of a set that came from a source an extension of the api adds, with its key.
export type IssueSourceResolver = (
  ids: number[] | SQLWrapper,
) => Promise<{ issueId: number; source: string }[]>;

let extension: IssueSourceResolver | null = null;

// Replaces the resolver an extension adds for the issues that came from a source of its own,
// such as a public form. Its keys are the ones it adds with setActorSources, so such an issue
// shows the icon its authors show with. A repository issue the issue is synced with names its
// source first.
export function setIssueSources(next: IssueSourceResolver | null = null): void {
  extension = next;
}

// The source of each issue of the set that came from somewhere, one query per resolver.
export async function issueSources(ids: number[] | SQLWrapper): Promise<Map<number, string>> {
  const byIssue = new Map<number, string>();
  if (Array.isArray(ids) && ids.length === 0) return byIssue;
  const [added, hosts] = await Promise.all([extension ? extension(ids) : [], repositoryHosts(ids)]);
  for (const row of [...added, ...hosts]) byIssue.set(row.issueId, row.source);
  return byIssue;
}

// Sets each issue's source. Mutates the passed issues in place.
export async function attachIssueSources<T extends { id: number; source: string | null }>(
  issues: T[],
  ids: number[] | SQLWrapper = issues.map((item) => item.id),
): Promise<void> {
  if (issues.length === 0) return;
  const byIssue = await issueSources(ids);
  for (const item of issues) item.source = byIssue.get(item.id) ?? null;
}

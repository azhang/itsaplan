import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { inArray } from 'drizzle-orm';
import { db, issue } from '@repo/db';
import { api as anonymous, authedApi, createProject } from '#tests/helpers/app';
import { signUpTestUser } from '#tests/helpers/auth';
import { resetDb } from '#tests/helpers/db';
import { setIssueSources } from '../../sources';

// Where an issue came from, beside a repository host (git-issue-sync.test.ts): the source an
// extension of the api names for its own issues through setIssueSources.

describe('Issue sources an extension adds', () => {
  beforeEach(resetDb);
  afterEach(() => setIssueSources());

  it('names the source of the issues an extension resolves, and none of the others', async () => {
    const owner = await signUpTestUser();
    const api = authedApi(owner.cookie);
    await createProject(api, { key: 'MKT', name: 'Marketing' });
    const project = api.projects({ projectKey: 'MKT' });
    const columnId = (await project.get()).data!.columns[0]!.id;
    const filed = (await project.issues.post({ columnId, title: 'From a form' })).data!;
    const plain = (await project.issues.post({ columnId, title: 'Made here' })).data!;

    setIssueSources(async (ids) => {
      const rows = await db.select({ id: issue.id }).from(issue).where(inArray(issue.id, ids));
      return rows
        .filter((row) => row.id === filed.id)
        .map((row) => ({ issueId: row.id, source: 'portal' }));
    });

    const board = (await project.issues.board.get()).data!.issues;
    expect(board.find((one) => one.id === filed.id)!.source).toBe('portal');
    expect(board.find((one) => one.id === plain.id)!.source).toBeNull();
    expect((await api.issues({ issueId: filed.id }).get()).data!.source).toBe('portal');

    setIssueSources();
    expect((await api.issues({ issueId: filed.id }).get()).data!.source).toBeNull();
  });

  it('names it where another issue, a search or a page lists the issue, and not on a public link', async () => {
    const owner = await signUpTestUser();
    const api = authedApi(owner.cookie);
    await createProject(api, { key: 'MKT', name: 'Marketing' });
    const project = api.projects({ projectKey: 'MKT' });
    const columnId = (await project.get()).data!.columns[0]!.id;
    const parent = (await project.issues.post({ columnId, title: 'Launch' })).data!;
    const filed = (
      await project.issues.post({ columnId, title: 'Zephyr request', parentId: parent.id })
    ).data!;
    setIssueSources(async (ids) => {
      const rows = await db.select({ id: issue.id }).from(issue).where(inArray(issue.id, ids));
      return rows
        .filter((row) => row.id === filed.id)
        .map((row) => ({ issueId: row.id, source: 'portal' }));
    });

    const link = await api
      .issues({ issueId: parent.id })
      .links.post({ targetIssueId: filed.id, kind: 'relates' });
    expect(link.data!.issue.source).toBe('portal');
    const detail = (await api.issues({ issueId: parent.id }).get()).data!;
    expect(detail.subtasks.map((one) => one.source)).toEqual(['portal']);
    expect(detail.links.map((one) => one.issue.source)).toEqual(['portal']);

    const hit = (await project.issues.search.get({ query: { q: 'zephyr' } })).data!;
    expect(hit.map((one) => one.source)).toEqual(['portal']);
    const everywhere = (await api.issues.search.get({ query: { q: 'zephyr' } })).data!;
    expect(everywhere.map((one) => one.source)).toEqual(['portal']);

    const page = (await project.documents.post({ title: 'Notes', content: '' })).data!;
    const linked = await project
      .documents({ documentId: page.id })
      .issues.post({ issueId: filed.id });
    expect(linked.data!.source).toBe('portal');
    const pageIssues = (await project.documents({ documentId: page.id }).issues.get()).data!;
    expect(pageIssues.map((one) => one.source)).toEqual(['portal']);

    const token = (await api.issues({ issueId: parent.id }).share.post()).data!.token;
    // The public route's response schema is t.Any().
    const shared = (await anonymous.share.issue({ token }).get()).data!.issue as {
      subtasks: { source: string | null }[];
      links: { issue: { source: string | null } }[];
    };
    expect(shared.subtasks.map((one) => one.source)).toEqual([null]);
    expect(shared.links.map((one) => one.issue.source)).toEqual([null]);
  });
});

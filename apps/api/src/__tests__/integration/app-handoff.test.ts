import { createHash, randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'bun:test';
import { db, user, verification } from '@repo/db';
import { eq, like } from 'drizzle-orm';
import { app } from '../helpers/app';
import { signUpTestUser } from '../helpers/auth';
import { resetDb } from '../helpers/db';

// The sign-in handoff for the native app shells (packages/auth/src/app-handoff.ts):
// the app signs in in the system browser and gets a session of its own, bound to a
// verifier only the app holds. The plugin is registered by src/app-handoff.ts, which has
// to run before any test uses auth. This file registers it itself, and is skipped when a
// test file before it already used auth. To be sure it runs, preload it:
//   bun test --env-file=../../.env.test --preload ./src/app-handoff.ts src/__tests__/integration/app-handoff.test.ts
const registered = await import('../../app-handoff').then(
  () => true,
  () => false,
);

interface Session {
  user: { id: string };
  session: { token: string };
}
interface SignIn {
  redirect?: boolean;
  url?: string;
  user: { id: string };
}

const AUTH = 'http://localhost:3000/api/auth';
const WEB = 'http://localhost:3001';

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge, state: randomBytes(16).toString('base64url') };
}

// Merges a response's Set-Cookie headers into a Cookie header, dropping expired ones.
function withCookies(cookie: string, response: Response): string {
  const jar = new Map(
    cookie
      .split('; ')
      .filter(Boolean)
      .map((c) => [c.slice(0, c.indexOf('=')), c] as const),
  );
  for (const set of response.headers.getSetCookie()) {
    const pair = set.split(';')[0]!;
    const name = pair.slice(0, pair.indexOf('='));
    if (/max-age=0/i.test(set) || pair.endsWith('=')) jar.delete(name);
    else jar.set(name, pair);
  }
  return [...jar.values()].join('; ');
}

const get = (path: string, cookie = '') =>
  app.handle(new Request(`${AUTH}${path}`, { headers: { cookie } }));

// The browser's part: start, confirm, and the token the app receives.
async function browserFlow(cookie: string, challenge: string, state: string) {
  const start = await get(`/app-handoff/start?challenge=${challenge}&state=${state}`, cookie);
  const jar = withCookies(cookie, start);
  const confirm = await get('/app-handoff/finish', jar);
  const page = await confirm.clone().text();
  const href = /href="([^"]+)"/.exec(page)?.[1]?.replaceAll('&amp;', '&') ?? '';
  const issued = await app.handle(new Request(href, { headers: { cookie: jar } }));
  const location = new URL(issued.headers.get('location') ?? 'about:blank');
  return { start, confirm, issued, location, token: location.searchParams.get('token') ?? '' };
}

// The app loads consume itself, so the request is not from any site.
const consume = (token: string, verifier: string, site = 'none') =>
  app.handle(
    new Request(`${AUTH}/app-handoff/consume?token=${token}&verifier=${verifier}`, {
      headers: { 'sec-fetch-site': site },
    }),
  );

if (!registered)
  console.warn('app-handoff.test.ts skipped: run it with src/app-handoff.ts preloaded');

describe.skipIf(!registered)('app sign-in handoff', () => {
  beforeEach(resetDb);

  // How the shells detect it.
  it('is listed in the auth OpenAPI document', async () => {
    const doc = (await (await get('/open-api/generate-schema')).json()) as {
      paths: Record<string, unknown>;
    };
    for (const route of ['start', 'finish', 'consume']) {
      expect(doc.paths).toHaveProperty([`/app-handoff/${route}`]);
    }
  });

  it('hands a signed-in browser session to the app as a new session', async () => {
    const browser = await signUpTestUser();
    const { verifier, challenge, state } = pkce();
    const flow = await browserFlow(browser.cookie, challenge, state);

    expect(flow.start.status).toBe(302);
    expect(flow.start.headers.get('location')).toBe(`${AUTH}/app-handoff/finish`);
    expect(flow.confirm.status).toBe(200);
    expect(await flow.confirm.text()).toContain(browser.email);
    expect(flow.issued.status).toBe(302);
    expect(flow.location.protocol).toBe('itsaplan:');
    expect(flow.location.searchParams.get('state')).toBe(state);

    const consumed = await consume(flow.token, verifier);
    expect(consumed.status).toBe(302);
    expect(consumed.headers.get('location')).toBe(WEB);
    const appCookie = withCookies('', consumed);
    const session = (await (await get('/get-session', appCookie)).json()) as Session;
    expect(session.user.id).toBe(browser.userId);
    const browserSession = (await (await get('/get-session', browser.cookie)).json()) as Session;
    expect(session.session.token).not.toBe(browserSession.session.token);
  });

  it('refuses a wrong verifier and spends the token anyway', async () => {
    const browser = await signUpTestUser();
    const { verifier, challenge, state } = pkce();
    const { token } = await browserFlow(browser.cookie, challenge, state);

    expect((await consume(token, pkce().verifier)).status).toBe(401);
    expect((await consume(token, verifier)).status).toBe(401);
  });

  it('refuses a consume link followed from a page (login CSRF)', async () => {
    const browser = await signUpTestUser();
    const { verifier, challenge, state } = pkce();
    const { token } = await browserFlow(browser.cookie, challenge, state);

    expect((await consume(token, verifier, 'cross-site')).status).toBe(403);
    expect((await consume(token, verifier, 'same-site')).status).toBe(403);
    expect((await consume(token, verifier)).status).toBe(302);
  });

  it('uses a token once', async () => {
    const browser = await signUpTestUser();
    const { verifier, challenge, state } = pkce();
    const { token } = await browserFlow(browser.cookie, challenge, state);

    expect((await consume(token, verifier)).status).toBe(302);
    expect((await consume(token, verifier)).status).toBe(401);
  });

  it('refuses an expired token', async () => {
    const browser = await signUpTestUser();
    const { verifier, challenge, state } = pkce();
    const { token } = await browserFlow(browser.cookie, challenge, state);
    await db
      .update(verification)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(like(verification.identifier, 'app-handoff:%'));

    expect((await consume(token, verifier)).status).toBe(401);
  });

  it('refuses a deactivated account', async () => {
    const browser = await signUpTestUser();
    const { verifier, challenge, state } = pkce();
    const { token } = await browserFlow(browser.cookie, challenge, state);
    await db.update(user).set({ active: false }).where(eq(user.id, browser.userId));

    const consumed = await consume(token, verifier);
    expect(consumed.status).toBe(403);
    expect(consumed.headers.getSetCookie().join()).not.toContain('session_token=');
  });

  it('rejects a malformed challenge or state', async () => {
    const { state, challenge } = pkce();
    expect((await get(`/app-handoff/start?challenge=short&state=${state}`)).status).toBe(400);
    expect((await get(`/app-handoff/start?challenge=${challenge}&state=x`)).status).toBe(400);
  });

  it("issues no token without the confirmation page's code", async () => {
    const browser = await signUpTestUser();
    const { challenge, state } = pkce();
    const start = await get(
      `/app-handoff/start?challenge=${challenge}&state=${state}`,
      browser.cookie,
    );
    const jar = withCookies(browser.cookie, start);
    for (const code of ['guessed', '']) {
      const forged = await get(`/app-handoff/finish?confirm=${code}`, jar);
      expect(forged.status).toBe(403);
      expect(forged.headers.get('location') ?? '').not.toStartWith('itsaplan:');
    }
  });

  it("keeps the confirmation page out of other sites' frames", async () => {
    const browser = await signUpTestUser();
    const { challenge, state } = pkce();
    const { confirm } = await browserFlow(browser.cookie, challenge, state);
    expect(confirm.headers.get('x-frame-options')).toBe('DENY');
    expect(confirm.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
  });

  it('sends a browser that is not signed in to the login page, then on to finish', async () => {
    const account = await signUpTestUser();
    const { challenge, state } = pkce();
    const start = await get(`/app-handoff/start?challenge=${challenge}&state=${state}`);
    expect(start.headers.get('location')).toBe(`${WEB}/login`);

    const signIn = await app.handle(
      new Request(`${AUTH}/sign-in/email`, {
        method: 'POST',
        headers: {
          cookie: withCookies('', start),
          origin: WEB,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ email: account.email, password: 'test-password-123' }),
      }),
    );
    const body = (await signIn.json()) as SignIn;
    expect(body).toMatchObject({ redirect: true, url: `${AUTH}/app-handoff/finish` });
    expect(body.user.id).toBe(account.userId);
  });

  it('leaves an ordinary sign-in alone', async () => {
    const account = await signUpTestUser();
    const signIn = await app.handle(
      new Request(`${AUTH}/sign-in/email`, {
        method: 'POST',
        headers: { origin: WEB, 'content-type': 'application/json' },
        body: JSON.stringify({ email: account.email, password: 'test-password-123' }),
      }),
    );
    const body = (await signIn.json()) as SignIn;
    expect(body.url).toBeUndefined();
  });
});

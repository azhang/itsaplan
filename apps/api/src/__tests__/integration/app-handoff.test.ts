import { createHash, randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'bun:test';
import { db, user, verification } from '@repo/db';
import { eq, like } from 'drizzle-orm';
import { api, app } from '../helpers/app';
import { signUpTestUser } from '../helpers/auth';
import { resetDb } from '../helpers/db';

// The sign-in handoff for the native app shells (packages/auth/src/app-handoff.ts):
// the app signs in in the system browser and gets a session of its own, bound to a
// verifier only the app holds.

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
  const issued = await app.handle(
    new Request(`${AUTH}/app-handoff/finish`, {
      method: 'POST',
      headers: { cookie: jar, origin: 'http://localhost:3000' },
    }),
  );
  const location = new URL(issued.headers.get('location') ?? 'about:blank');
  return { start, confirm, issued, location, token: location.searchParams.get('token') ?? '' };
}

const consume = (token: string, verifier: string) =>
  get(`/app-handoff/consume?token=${token}&verifier=${verifier}`);

describe('app sign-in handoff', () => {
  beforeEach(resetDb);

  it('is advertised in the auth config', async () => {
    expect((await api['auth-config'].get()).data).toMatchObject({ appHandoff: true });
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

  it('issues no token on a cross-site POST', async () => {
    const browser = await signUpTestUser();
    const { challenge, state } = pkce();
    const start = await get(
      `/app-handoff/start?challenge=${challenge}&state=${state}`,
      browser.cookie,
    );
    const forged = await app.handle(
      new Request(`${AUTH}/app-handoff/finish`, {
        method: 'POST',
        headers: { cookie: withCookies(browser.cookie, start), origin: 'https://evil.example' },
      }),
    );
    expect(forged.status).toBe(403);
    expect(forged.headers.get('location') ?? '').not.toStartWith('itsaplan:');
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

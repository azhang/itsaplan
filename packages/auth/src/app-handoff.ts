import { createHash, timingSafeEqual } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import {
  createAuthEndpoint,
  createAuthMiddleware,
  getSessionFromCtx,
  sessionMiddleware,
} from 'better-auth/api';
import { expireCookie, setSessionCookie } from 'better-auth/cookies';
import { generateRandomString } from 'better-auth/crypto';

// Sign-in handoff for the native app shells (macOS, iOS). Their embedded web view
// cannot run passkeys, security keys or Google sign-in, so the app signs in in the
// system browser and is handed a session of its own:
//
//   1. The app makes a random verifier, and opens `start` in the browser with
//      challenge = base64url(sha256(verifier)) and a state of its own.
//   2. The browser signs in however the instance allows. An after-hook sees the new
//      session and sends the browser to `finish` instead of the app.
//   3. `finish` asks the user to confirm, then redirects to itsaplan://auth with a
//      single-use token that lives three minutes.
//   4. The app opens `consume` in its web view with the token and the verifier, which
//      creates a new session there. Only an app-started navigation may open it.
//
// Any app can claim the itsaplan:// scheme, so a token alone is worthless: `consume`
// also needs the verifier, which never left the app (PKCE, RFC 7636). The confirmation
// in step 3 stops another local app from starting its own flow and getting a token
// silently from a browser that is already signed in. The return target is fixed; the
// request never names one. Tokens are stored hashed in the verification table, so
// this adds no table.

const COOKIE = 'app_handoff';
const RETURN_URL = 'itsaplan://auth';
const TOKEN_TTL_MS = 3 * 60 * 1000;
const FLOW_TTL_S = 10 * 60;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/; // base64url SHA-256, no padding
const STATE = /^[A-Za-z0-9_-]{16,128}$/;
const VERIFIER = /^[A-Za-z0-9_~.-]{43,128}$/; // RFC 7636 §4.1

interface Flow {
  challenge: string;
  state: string;
  // Known only to this browser's confirmation page; the Continue link carries it.
  confirm: string;
}

const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url');

function sameDigest(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

function confirmPage(email: string, href: string): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in to the app</title>
<style>body{font:15px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#fafafa;color:#171717}
main{max-width:360px;padding:16px}a{display:inline-block;font:inherit;padding:8px 16px;border-radius:8px;background:#08090a;color:#fbfbfa;text-decoration:none}
@media (prefers-color-scheme:dark){body{background:#131313;color:#f5f5f5}a{background:#fbfbfa;color:#08090a}}</style></head>
<body><main><h1 style="font-size:20px">Sign in to the It's a Plan app?</h1>
<p>The app on this device will be signed in as <strong>${escapeHtml(email)}</strong>. Continue only if you just asked the app to sign in.</p>
<a href="${escapeHtml(href)}">Continue</a></main></body></html>`;
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      // Never inside another site's frame, where a click could be tricked out of the user.
      'content-security-policy':
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
  });
}

export function appHandoff(webOrigin: string) {
  return {
    id: 'app-handoff',
    endpoints: {
      appHandoffStart: createAuthEndpoint('/app-handoff/start', { method: 'GET' }, async (ctx) => {
        const challenge = String(ctx.query?.challenge ?? '');
        const state = String(ctx.query?.state ?? '');
        if (!CHALLENGE.test(challenge) || !STATE.test(state)) {
          throw ctx.error('BAD_REQUEST', { message: 'Invalid challenge or state' });
        }
        const flow: Flow = { challenge, state, confirm: generateRandomString(32) };
        await ctx.setSignedCookie(COOKIE, JSON.stringify(flow), ctx.context.secret, {
          ...ctx.context.authCookies.sessionToken.attributes,
          maxAge: FLOW_TTL_S,
        });
        const session = await getSessionFromCtx(ctx).catch(() => null);
        throw ctx.redirect(
          session ? `${ctx.context.baseURL}/app-handoff/finish` : `${webOrigin}/login`,
        );
      }),

      // Without `confirm`, asks the signed-in browser to confirm. Its Continue link
      // comes back with the flow's confirm code, which only that page knows, so a page
      // elsewhere can't confirm on the user's behalf. A link, not a form: better-auth
      // refuses a POST whose Origin is null, which some browsers send here.
      appHandoffFinish: createAuthEndpoint(
        '/app-handoff/finish',
        { method: 'GET', use: [sessionMiddleware] },
        async (ctx) => {
          const raw = await ctx.getSignedCookie(COOKIE, ctx.context.secret);
          const flow = raw ? (JSON.parse(raw) as Flow) : null;
          if (
            !flow ||
            !CHALLENGE.test(flow.challenge) ||
            !STATE.test(flow.state) ||
            typeof flow.confirm !== 'string'
          ) {
            throw ctx.redirect(webOrigin);
          }
          const confirm = ctx.query?.confirm;
          if (confirm == null) {
            const href = `${ctx.context.baseURL}/app-handoff/finish?confirm=${flow.confirm}`;
            return confirmPage(ctx.context.session.user.email, href);
          }
          if (!sameDigest(String(confirm), flow.confirm)) {
            throw ctx.error('FORBIDDEN', { message: 'Confirm the sign-in from its own page' });
          }
          expireCookie(ctx, {
            name: COOKIE,
            attributes: ctx.context.authCookies.sessionToken.attributes,
          });
          const token = generateRandomString(43);
          await ctx.context.internalAdapter.createVerificationValue({
            identifier: `app-handoff:${sha256(token)}`,
            value: JSON.stringify({
              userId: ctx.context.session.user.id,
              challenge: flow.challenge,
            }),
            expiresAt: new Date(Date.now() + TOKEN_TTL_MS),
          });
          throw ctx.redirect(`${RETURN_URL}?token=${token}&state=${flow.state}`);
        },
      ),

      appHandoffConsume: createAuthEndpoint(
        '/app-handoff/consume',
        { method: 'GET' },
        async (ctx) => {
          const token = String(ctx.query?.token ?? '');
          const verifier = String(ctx.query?.verifier ?? '');
          // Only a navigation the app starts itself (Sec-Fetch-Site: none). A link to
          // here from any page, even this server's, would let someone sign the reader
          // in to an account of their own (login CSRF).
          if (ctx.request?.headers.get('sec-fetch-site') !== 'none') {
            throw ctx.error('FORBIDDEN', { message: 'Open this from the app' });
          }
          if (!token || !VERIFIER.test(verifier)) {
            throw ctx.error('BAD_REQUEST', { message: 'Invalid token or verifier' });
          }
          // Consumed before any check, so a token is spent even by a failed attempt.
          const stored = await ctx.context.internalAdapter.consumeVerificationValue(
            `app-handoff:${sha256(token)}`,
          );
          const grant = stored
            ? (JSON.parse(stored.value) as { userId: string; challenge: string })
            : null;
          if (
            !stored ||
            !grant ||
            stored.expiresAt < new Date() ||
            !sameDigest(sha256(verifier), grant.challenge)
          ) {
            throw ctx.error('UNAUTHORIZED', { message: 'Invalid or expired sign-in token' });
          }
          const user = await ctx.context.internalAdapter.findUserById(grant.userId);
          if (!user)
            throw ctx.error('UNAUTHORIZED', { message: 'Invalid or expired sign-in token' });
          // A session of its own: signing out in the browser leaves the app signed in.
          // The session create hook refuses a deactivated account here as everywhere.
          const session = await ctx.context.internalAdapter.createSession(user.id);
          await setSessionCookie(ctx, { session, user });
          throw ctx.redirect(webOrigin);
        },
      ),
    },
    hooks: {
      after: [
        {
          matcher: (ctx) => !ctx.path?.startsWith('/app-handoff/'),
          // A sign-in during a handoff goes on to `finish`. A redirect flow (OAuth
          // callback, magic link) is redirected; a sign-in made by fetch (password,
          // passkey) gets `{ redirect, url }`, which the auth client follows.
          handler: createAuthMiddleware(async (ctx) => {
            if (!ctx.context.newSession) return;
            if (!(await ctx.getSignedCookie(COOKIE, ctx.context.secret))) return;
            const finish = `${ctx.context.baseURL}/app-handoff/finish`;
            if (ctx.request?.method === 'GET') throw ctx.redirect(finish);
            const returned = ctx.context.returned;
            const body =
              returned && typeof returned === 'object' && !(returned instanceof Response)
                ? returned
                : {};
            return ctx.json({ ...body, redirect: true, url: finish });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}

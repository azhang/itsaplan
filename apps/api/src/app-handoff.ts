import { extendAuth } from '@repo/auth/extensions';
import { appHandoff } from '../../../packages/auth/src/app-handoff';

// This fork's api entry: upstream's ./index.ts plus the native-app sign-in handoff
// (packages/auth/src/app-handoff.ts), added through upstream's own extendAuth, so no
// upstream file has to change. Run this instead of ./index.ts. extendAuth must run before
// the auth instance is first used, so ./index.ts is imported only after it. The handoff
// test preloads this file to register the plugin without starting the server.

const webOrigin = (process.env.APP_URL ?? '').split(',')[0]!.trim().replace(/\/+$/, '');
extendAuth({ plugins: [appHandoff(webOrigin)] });

if (import.meta.main) await import('./index');

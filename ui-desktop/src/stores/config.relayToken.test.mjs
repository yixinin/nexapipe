/**
 * The rule that keeps a relay's token with the relay it was issued for.
 *
 * The desktop frontend has no test runner, so this file is a plain Node
 * test, run through Vite's own SSR build — the only bundler the tree has,
 * and the one that already resolves this tree's extensionless imports. The
 * desktop CI job runs it (`npm run test:stores`), which builds each of the
 * store's test files and runs it:
 *
 *   cd ui-desktop
 *   npx vite build --ssr src/stores/config.relayToken.test.mjs --outDir dist-ssr
 *   node dist-ssr/config.relayToken.test.js
 *
 * It is a `.mjs` file because the tree has no `@types/node`: a TypeScript
 * test would fail `vue-tsc` on `node:test` before it ever ran.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * What the backend answers for each command.
 *
 * The store talks to the backend over the Tauri IPC, and the relay token
 * lives in the credential store on the other side of it — so the backend is
 * what decides what the store reads back. The map is what a test writes an
 * answer into; a command with no answer answers `null`, which is what an
 * empty credential store says.
 */
const answers = new Map();

/**
 * The browser globals the store expects.
 *
 * `localStorage` holds the configuration payload, and `window.__TAURI_INTERNALS__`
 * is where Tauri's `invoke` sends every command. Both are set before the
 * store is imported, because the store reads the configuration while it is
 * being imported.
 */
globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
};

globalThis.window = {
  __TAURI_INTERNALS__: {
    invoke: async (cmd) => {
      const answer = answers.get(cmd);
      return answer === undefined ? null : answer;
    },
  },
};

const { relayTokenRelayFor, relayTokenToSend, useConfigStore } = await import('./config');
const { dismissAll, useToast } = await import('../composables/useToast');
const { translate } = await import('../i18n');

/**
 * The store, with nothing in it.
 *
 * The store is a module singleton — that is what makes it the app's one
 * configuration — so a test that leaves a token behind would hand it to the
 * next one. `resetConfig` empties it.
 */
function freshStore() {
  const store = useConfigStore();
  store.resetConfig();
  // The notices a previous test raised are not this test's business, and
  // their timers would keep the process alive after the last one.
  dismissAll();
  return store;
}

/** A relay with a token issued for it. */
function configuredRelay(store, url, token) {
  store.setRelayUrl(url);
  store.setRelayAuthToken(token);
}

test('a change of the relay URL clears the token', () => {
  const store = freshStore();
  configuredRelay(store, 'https://relay-a.example', 'token-a');

  assert.equal(store.config.relayAuthToken, 'token-a');
  assert.equal(store.config.relayAuthTokenRelay, 'https://relay-a.example');

  store.setRelayUrl('https://relay-b.example');

  assert.equal(store.config.relayAuthToken, '');
  assert.equal(store.config.relayAuthTokenRelay, '');
});

test('an invite that names a relay does not carry the token over to it', async () => {
  const store = freshStore();
  configuredRelay(store, 'https://relay-a.example', 'token-a');

  answers.set('accept_invite', {
    nodeId: 'node-1',
    connectionType: 'endpoint_id',
    existing: false,
    domains: ['example.com'],
    relay: 'https://relay-b.example',
  });
  answers.set('take_invited_node_credentials', {
    totp: null,
    enrollment: null,
    deviceKey: null,
    ticket: null,
    endpoint: 'endpoint-1',
  });

  await store.applyInvite('nexapipe://invite', { applyRelay: true });

  assert.equal(store.config.relayUrl, 'https://relay-b.example');
  assert.equal(store.config.relayAuthToken, '');
  assert.equal(store.config.relayAuthTokenRelay, '');
});

test('an invite that is not adopted as the relay leaves the token alone', async () => {
  const store = freshStore();
  configuredRelay(store, 'https://relay-a.example', 'token-a');

  answers.set('accept_invite', {
    nodeId: 'node-2',
    connectionType: 'endpoint_id',
    existing: false,
    domains: ['example.com'],
    relay: 'https://relay-b.example',
  });
  answers.set('take_invited_node_credentials', {
    totp: null,
    enrollment: null,
    deviceKey: null,
    ticket: null,
    endpoint: 'endpoint-2',
  });

  await store.applyInvite('nexapipe://invite', { applyRelay: false });

  assert.equal(store.config.relayUrl, 'https://relay-a.example');
  assert.equal(store.config.relayAuthToken, 'token-a');
});

test('the token the user typed is stored, bound to the relay it was typed for', () => {
  const store = freshStore();
  store.setRelayUrl('https://relay-a.example');

  store.setRelayAuthToken('token-a');

  assert.equal(store.config.relayAuthToken, 'token-a');
  assert.equal(store.config.relayAuthTokenRelay, 'https://relay-a.example');
});

test('a token survives a re-save of the same relay URL', () => {
  const store = freshStore();
  configuredRelay(store, 'https://relay-a.example', 'token-a');

  store.setRelayUrl('https://relay-a.example');

  assert.equal(store.config.relayAuthToken, 'token-a');
  assert.equal(store.config.relayAuthTokenRelay, 'https://relay-a.example');
});

test('a change of the mode alone keeps the token', () => {
  const store = freshStore();
  configuredRelay(store, 'https://relay-a.example', 'token-a');

  store.setRelayMode('disabled');

  assert.equal(store.config.relayMode, 'disabled');
  assert.equal(store.config.relayUrl, 'https://relay-a.example');
  assert.equal(store.config.relayAuthToken, 'token-a');
});

test('the general setter cannot carry the token to another relay either', () => {
  const store = freshStore();
  store.updateConfig({ relayUrl: 'https://relay-a.example' });
  store.updateConfig({ relayAuthToken: 'token-a' });

  store.updateConfig({ relayUrl: 'https://relay-b.example' });

  assert.equal(store.config.relayAuthToken, '');
  assert.equal(store.config.relayAuthTokenRelay, '');
});

test('the proxy is not handed a token that belongs to another relay', () => {
  const issued = { token: 'token-a', relay: 'https://relay-a.example' };

  assert.equal(relayTokenToSend(issued, 'https://relay-b.example'), '');
  assert.equal(relayTokenToSend(issued, 'https://relay-a.example'), 'token-a');
  assert.equal(relayTokenToSend({ token: 'token-a', relay: '' }, 'https://relay-a.example'), '');
});

test('a dropped token is reported to the user', () => {
  const store = freshStore();
  configuredRelay(store, 'https://relay-a.example', 'token-a');

  store.setRelayUrl('https://relay-b.example');

  const { toasts } = useToast();
  const warnings = toasts.value.filter((toast) => toast.tone === 'warning');
  assert.ok(
    warnings.some((toast) => toast.message === translate('config.relayTokenCleared')),
    'the drop is not said out loud',
  );
});

test('a token read back from the credential store is bound to the relay in use', () => {
  // A token stored before the pairing existed has no recorded relay: it
  // belongs to the relay the configuration names, which is the one it was
  // last used with.
  assert.equal(relayTokenRelayFor('https://relay-a.example', ''), 'https://relay-a.example');
  // A payload that does record one keeps it.
  assert.equal(
    relayTokenRelayFor('https://relay-b.example', 'https://relay-a.example'),
    'https://relay-a.example',
  );
});

/**
 * What a node's 2FA reads as, and what a handshake answers with.
 *
 * Two rules that have to be the same on this side and on the wire, because the
 * page and the handshake are asked the same question in different words: does
 * this node hold a credential?
 *
 * The first is the state the page shows. A node that is waiting to enroll has
 * no credential yet — it has a token, and the token is armed — so reading it
 * as "2FA off" made a scanned invite look like it had not been applied at all.
 *
 * The second is the credential itself. A key belongs to the machine rather
 * than to the node, so every node of a machine that has one carries it, and a
 * node that carries a key is not thereby holding a credential: the key is an
 * offer until the enrollment that the server answers has named the device it
 * was issued to. The rule is the one the handshake uses (`manager.rs`), so the
 * page cannot disagree with it about whether a node authenticates at all.
 *
 * The desktop frontend has no test runner, so this file is a plain Node
 * test, run through Vite's own SSR build — the only bundler the tree has,
 * and the one that already resolves this tree's extensionless imports. The
 * desktop CI job runs it (`npm run test:stores`), which builds each of the
 * store's test files and runs it:
 *
 *   cd ui-desktop
 *   npx vite build --ssr src/stores/config.twoFactor.test.mjs --outDir dist-ssr
 *   node dist-ssr/config.twoFactor.test.js
 *
 * It is a `.mjs` file because the tree has no `@types/node`: a TypeScript
 * test would fail `vue-tsc` on `node:test` before it ever ran.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * The browser globals the store expects.
 *
 * `localStorage` holds the configuration payload, and `window.__TAURI_INTERNALS__`
 * is where Tauri's `invoke` sends every command. Both are set before the store
 * is imported, because the store reads the configuration while it is being
 * imported.
 */
globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
};

globalThis.window = {
  __TAURI_INTERNALS__: {
    invoke: async () => null,
  },
};

const { hasTwoFactor, twoFactorState } = await import('./config/nodes');

/** A node, as the configuration holds it. */
function node(overrides = {}) {
  return {
    id: 'node-1',
    connectionType: 'endpoint_id',
    ticket: '',
    endpointId: 'a'.repeat(64),
    domains: [],
    ...overrides,
  };
}

/** A node that enrolled with a secret. */
function withSecret(overrides = {}) {
  return node({
    twoFactor: { clientId: 'client-001', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'sha1' },
    ...overrides,
  });
}

/** A node that enrolled with a key: no secret, a device name, and the key. */
function withKey(overrides = {}) {
  return node({
    twoFactor: { clientId: 'client-001', secret: '', algorithm: 'sha1', device: 'laptop' },
    deviceKey: 'ab'.repeat(32),
    ...overrides,
  });
}

test('a node with a credential reads as on', () => {
  assert.equal(twoFactorState(withSecret()), 'on');
  assert.equal(twoFactorState(withKey()), 'on');
});

test('a node without one reads as off', () => {
  assert.equal(twoFactorState(node()), 'off');
  // A record with an empty secret and no device name is not a credential: it
  // is the shape an invite leaves behind.
  assert.equal(
    twoFactorState(node({ twoFactor: { clientId: '', secret: '', algorithm: 'sha1' } })),
    'off',
  );
});

test('a node waiting to enroll reads as pending, not off', () => {
  const pending = node({
    enrollment: { clientId: 'client-001', token: 'tok', device: 'laptop' },
    // The key is on file already — it is what the enrollment will offer — and
    // it must not make the node read as one that already holds a credential.
    deviceKey: 'ab'.repeat(32),
    twoFactor: { clientId: '', secret: '', algorithm: 'sha1' },
  });

  assert.equal(twoFactorState(pending), 'pending');
});

test('a key counts only once it names the device it was issued to', () => {
  // The key is an offer until the enrollment has been answered: the server
  // records the public half under a device name, and without that name there
  // is nothing on the server to answer with.
  const offered = node({
    twoFactor: { clientId: 'client-001', secret: '', algorithm: 'sha1' },
    deviceKey: 'ab'.repeat(32),
  });

  assert.equal(hasTwoFactor(offered), false);
  assert.equal(twoFactorState(offered), 'off');
});

test('a secret wins over a key', () => {
  // A server that ignored the key and issued a secret instead: the secret is
  // what it holds, and it is what the handshake answers with.
  const both = node({
    twoFactor: {
      clientId: 'client-001',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'sha1',
      device: 'laptop',
    },
    deviceKey: 'ab'.repeat(32),
  });

  assert.equal(hasTwoFactor(both), true);
});

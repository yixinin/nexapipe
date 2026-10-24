/**
 * The credential an invite brings, and the proxy that has to spend it.
 *
 * A registration invite carries a one-time token instead of a secret. The
 * token is filed in the credential store, and the proxy spends it on its first
 * connection — which is the only moment the credential exists, because the
 * server forgets the token in the same write that issues the secret.
 *
 * The proxy runs in another process when the service owns the tunnel, and
 * that process has no credential store of its own: the token has to travel
 * with the start-up request. It did not, and a node whose token stayed in the
 * store was a node that opened no auth stream at all — the server answered
 * every connection with "2FA required", and nothing was ever proxied.
 *
 * The desktop frontend has no test runner, so this file is a plain Node
 * test, run through Vite's own SSR build — the only bundler the tree has,
 * and the one that already resolves this tree's extensionless imports. The
 * desktop CI job runs it (`npm run test:stores`), which builds each of the
 * store's test files and runs it:
 *
 *   cd ui-desktop
 *   npx vite build --ssr src/stores/config.enrollment.test.mjs --outDir dist-ssr
 *   node dist-ssr/config.enrollment.test.js
 *
 * It is a `.mjs` file because the tree has no `@types/node`: a TypeScript
 * test would fail `vue-tsc` on `node:test` before it ever ran.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * What the backend answers for each command.
 *
 * The store talks to the backend over the Tauri IPC, and the credentials live
 * in the store on the other side of it. An answer may be a function, which is
 * how a test observes the app at the moment a command is in flight.
 */
const answers = new Map();

/** Every command the store made, in order, with the arguments it was given. */
const calls = [];

/**
 * The configuration payload, as `localStorage` holds it.
 *
 * A map rather than a stub, because this file writes one: the payload is read
 * while the store is being imported, so a node that has to be hydrated has to
 * be there before that happens.
 */
const payloads = new Map();

/**
 * Every write the store made, in order.
 *
 * The seed below goes into the map directly, so it is not in here. That is the
 * difference between "the payload holds no token" and "the payload holds no
 * token because nothing was written at all": a test that reads the seed proves
 * nothing about what the store does.
 */
const writes = [];

/**
 * The browser globals the store expects.
 *
 * `localStorage` holds the configuration payload, and `window.__TAURI_INTERNALS__`
 * is where Tauri's `invoke` sends every command. Both are set before the store
 * is imported, because the store reads the configuration while it is being
 * imported.
 */
globalThis.localStorage = {
  getItem: (key) => payloads.get(key) ?? null,
  setItem: (key, value) => {
    writes.push({ key, value });
    payloads.set(key, value);
  },
  removeItem: (key) => {
    payloads.delete(key);
  },
};

globalThis.window = {
  __TAURI_INTERNALS__: {
    invoke: async (cmd, args) => {
      calls.push({ cmd, args });
      const answer = answers.get(cmd);
      if (typeof answer === 'function') return await answer(args);
      return answer === undefined ? null : answer;
    },
  },
};

/**
 * A configuration as a machine that imported a registration invite left it.
 *
 * The payload is the *shape* of the configuration: the token itself is in the
 * credential store, and the payload says only that this node is waiting for a
 * credential and under which device name.
 */
payloads.set(
  'nexapipe.config',
  JSON.stringify({
    version: 3,
    nodes: [
      {
        id: 'node-1',
        connectionType: 'endpoint_id',
        ticket: '',
        endpointId: '',
        domains: ['example.com'],
        deviceKey: '',
        twoFactor: { clientId: '', secret: '', algorithm: 'sha1' },
        enrollment: { clientId: 'client-1', token: '', device: 'device-1' },
      },
    ],
    domains: [],
    deviceId: 'nexa-test-device',
  }),
);

const { initConfigStore, useConfigStore } = await import('./config');
const { dismissAll } = await import('../composables/useToast');

/**
 * The start-up read of the credential store.
 *
 * The mirror that writes the configuration's credentials back into the store
 * only runs once the store has answered at start-up — before that, an empty
 * credential reads as "not read back yet" rather than as "cleared". So the
 * read is done here: without it the mirror never runs, and the test about the
 * credential the invite filed would pass for the wrong reason.
 */
answers.set('take_runtime_credentials', {
  relay: null,
  nodes: {
    'node-1': {
      totp: null,
      enrollment: 'token-1',
      deviceKey: null,
      publicKey: null,
      ticket: null,
      endpoint: 'endpoint-1',
    },
  },
});
await initConfigStore();

/**
 * The store, with nothing in it.
 *
 * The store is a module singleton — that is what makes it the app's one
 * configuration — so a test that leaves a node behind would hand it to the
 * next one. `resetConfig` empties it.
 */
function freshStore() {
  const store = useConfigStore();
  store.resetConfig();
  // The notices a previous test raised are not this test's business, and
  // their timers would keep the process alive after the last one.
  dismissAll();
  calls.length = 0;
  return store;
}

test('a restart keeps the device the enrollment names', () => {
  const store = useConfigStore();

  const node = store.config.nodes.find((candidate) => candidate.id === 'node-1');
  assert.ok(node, 'the node is in the configuration');
  assert.equal(node.enrollment.token, 'token-1', 'the token is read back from the store');
  assert.equal(
    node.enrollment.device,
    'device-1',
    'the device the enrollment names is kept: enrolling without one answers with the ' +
      "client's own secret, which is what makes a revocation rotate every other device",
  );
});

test('the enrollment token the backend filed reaches the node the proxy is given', async () => {
  const store = freshStore();
  // A machine that already has a name, so the import does not have to ask the
  // operating system for one.
  store.config.deviceId = 'nexa-test-device';

  answers.set('accept_invite', {
    nodeId: 'node-2',
    connectionType: 'endpoint_id',
    existing: false,
    domains: ['example.com'],
    enrollment: { clientId: 'client-2' },
    publicKey: 'aa'.repeat(32),
  });
  answers.set('take_invited_node_credentials', {
    totp: null,
    enrollment: 'token-2',
    deviceKey: 'bb'.repeat(32),
    publicKey: 'aa'.repeat(32),
    ticket: null,
    endpoint: 'endpoint-2',
  });

  await store.applyInvite('nexapipe://invite');

  const node = store.config.nodes.find((candidate) => candidate.id === 'node-2');
  assert.ok(node, 'the node is in the configuration');
  assert.equal(
    node.enrollment.token,
    'token-2',
    'the proxy is given the token to spend: it is the only moment the token exists',
  );
});

test('the persisted payload holds no token', async () => {
  const store = freshStore();

  // Let the save the test before this one scheduled land, and forget it:
  // what is asserted below has to be a write *this* test caused.
  await new Promise((resolve) => setTimeout(resolve, 700));
  writes.length = 0;

  // A node that holds a token in memory. The payload is the *shape* of the
  // configuration: the token itself belongs in the credential store, and a
  // payload that carried it would be a copy of it in the clear.
  store.config.nodes.push({
    id: 'node-token',
    connectionType: 'endpoint_id',
    ticket: '',
    endpointId: '',
    domains: [],
    enrollment: { clientId: 'client-token', token: 'token-secret', device: 'device-1' },
  });

  // The save is debounced, so the mirror that writes the payload runs a
  // moment after the configuration changed.
  await new Promise((resolve) => setTimeout(resolve, 700));

  assert.ok(writes.length > 0, 'the store wrote a payload');

  // The payload the store wrote, not the one this file seeded: a seed is
  // read back as "no token" whatever the store does.
  const payload = JSON.parse(writes[writes.length - 1].value);
  assert.ok(
    payload.nodes?.some((node) => node.id === 'node-token'),
    'the node is in the payload the store wrote',
  );

  for (const node of payload.nodes ?? []) {
    assert.equal(
      node.enrollment?.token ?? '',
      '',
      `the payload keeps no token for ${node.id}: it belongs in the credential store`,
    );
  }
});

/**
 * The mirror that writes the configuration's credentials back into the store.
 *
 * The configuration holds the *shape* of a node's credentials and the store
 * holds the values, and the mirror is what keeps the two in step: written
 * when a node has a credential, deleted when it does not.
 *
 * What it must not do is delete a credential the user never cleared — and a
 * node whose credential is a secret carries the machine's key all the same,
 * because a key belongs to the machine rather than to the node. A rule that
 * asked "does this node have a key?" of the key the node *answers with* would
 * have deleted the seed the invite had just filed, and the node would have
 * started with no credential at all.
 *
 * The desktop frontend has no test runner, so this file is a plain Node
 * test, run through Vite's own SSR build — the only bundler the tree has,
 * and the one that already resolves this tree's extensionless imports. The
 * desktop CI job runs it (`npm run test:stores`), which builds each of the
 * store's test files and runs it:
 *
 *   cd ui-desktop
 *   npx vite build --ssr src/stores/config.credentials.test.mjs --outDir dist-ssr
 *   node dist-ssr/config.credentials.test.js
 *
 * It is a `.mjs` file because the tree has no `@types/node`: a TypeScript
 * test would fail `vue-tsc` on `node:test` before it ever ran.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Every credential the mirror wrote or deleted.
 *
 * The store talks to the backend over the Tauri IPC, and the credentials live
 * in the store on the other side of it: what the mirror did is what the store
 * was told.
 */
const calls = [];

/**
 * What the backend answers for each command.
 *
 * The credential store is read once, at start-up, and the answer is a bundle
 * of every credential the app runs on.
 */
const answers = new Map();

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
    invoke: async (cmd, args) => {
      calls.push({ cmd, args });
      // The answer comes on a macrotask, not in the microtask a promise that
      // is already resolved would resume in. An `await invoke(...)` has to
      // yield to the event loop for the store's own work to be observable:
      // with an immediate answer every command ran inside one microtask
      // drain, and nothing else could happen in between — not the debounced
      // save, and not a change made while the store was still working.
      await new Promise((resolve) => setTimeout(resolve, 0));
      const answer = answers.get(cmd);
      if (typeof answer === 'function') return await answer(args);
      return answer === undefined ? null : answer;
    },
  },
};

const { hydrateCredentials, markCredentialsHydrated, persistCredentials } = await import(
  './config/credentials'
);

/**
 * The mirror only runs once the store has answered.
 *
 * Before that, an empty credential reads as "not read back yet" rather than as
 * "cleared", and a mirror that ran in that window would take the credentials
 * it has not read out of the store.
 */
markCredentialsHydrated();

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

/** A configuration holding the nodes a test names. */
function configWith(nodes) {
  return {
    relayAuthToken: '',
    nodes,
  };
}

/** The credentials of one kind the mirror deleted. */
function deleted(kind) {
  return calls
    .filter((call) => call.cmd === 'delete_credential' && call.args.kind === kind)
    .map((call) => call.args.nodeId);
}

/** The credentials of one kind the mirror wrote. */
function written(kind) {
  return calls
    .filter((call) => call.cmd === 'put_credential' && call.args.kind === kind)
    .map((call) => call.args.nodeId);
}

test('a node whose credential is a secret keeps it, key of the machine or not', async () => {
  calls.length = 0;

  // A plain invite: the seed is in the store and the renderer does not hold
  // it — that is what `applyInvite` leaves behind. The machine's key is here
  // too, because the machine has one and every node of it carries it.
  await persistCredentials(
    configWith([
      node({
        twoFactor: { clientId: 'client-001', secret: '', algorithm: 'sha1' },
        deviceKey: 'ab'.repeat(32),
      }),
    ]),
  );

  assert.deepEqual(
    deleted('totp'),
    [],
    'the secret the invite filed was taken out of the store',
  );
});

test('a node whose credential is a key stores no seed', async () => {
  calls.length = 0;

  await persistCredentials(
    configWith([
      node({
        twoFactor: { clientId: 'client-001', secret: '', algorithm: 'sha1', device: 'laptop' },
        // The node's own key: the one it enrolled with.
        publicKey: 'cd'.repeat(32),
        deviceKey: 'ab'.repeat(32),
      }),
    ]),
  );

  assert.deepEqual(deleted('totp'), ['node-1']);
});

test("a node's own key is left in the store", async () => {
  calls.length = 0;

  await persistCredentials(
    configWith([
      node({
        twoFactor: { clientId: 'client-001', secret: '', algorithm: 'sha1', device: 'laptop' },
        publicKey: 'cd'.repeat(32),
        deviceKey: 'ab'.repeat(32),
      }),
    ]),
  );

  assert.deepEqual(
    deleted('devicekey'),
    [],
    "the node's own key was taken out of the store",
  );
});

test('a node that has no key of its own leaves none behind', async () => {
  calls.length = 0;

  await persistCredentials(
    configWith([
      node({
        twoFactor: { clientId: 'client-001', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'sha1' },
        // The machine's key only: this node never enrolled with one of its own.
        deviceKey: 'ab'.repeat(32),
      }),
    ]),
  );

  assert.deepEqual(deleted('devicekey'), ['node-1']);
  assert.deepEqual(written('totp'), ['node-1'], 'the secret is written back');
});

test('the read fills a copy, not the configuration it was given', async () => {
  calls.length = 0;

  answers.set('take_runtime_credentials', {
    relay: null,
    nodes: {
      'node-1': {
        totp: null,
        enrollment: null,
        deviceKey: null,
        publicKey: null,
        ticket: null,
        endpoint: 'endpoint-1',
      },
      'node-2': {
        totp: null,
        enrollment: null,
        deviceKey: null,
        publicKey: null,
        ticket: null,
        endpoint: 'endpoint-2',
      },
    },
  });

  // The configuration the app runs on: two nodes whose credentials are in the
  // store and not in the configuration, which is what a version-3 payload
  // holds.
  const source = configWith([
    node({ id: 'node-1', endpointId: '', deviceKey: 'ab'.repeat(32) }),
    node({ id: 'node-2', endpointId: '' }),
  ]);

  const hydration = hydrateCredentials(source);

  // The read is in flight: the backend has answered, and the store is still
  // being read node by node. Nothing else could happen in this window before,
  // because the answer used to come back inside the same microtask the
  // command was sent in.
  await new Promise((resolve) => setTimeout(resolve, 0));

  const hydrated = await hydration;

  // The configuration the app runs on was not filled in place. A node-by-node
  // fill would expose a configuration whose first node has been read and
  // whose second has not, and a save started there would take the second
  // node's credentials out of the store as if the user had cleared them.
  assert.deepEqual(
    source.nodes.map((candidate) => candidate.endpointId),
    ['', ''],
    'the configuration was filled in place while the store was being read',
  );
  assert.deepEqual(
    hydrated.nodes.map((candidate) => candidate.endpointId),
    ['endpoint-1', 'endpoint-2'],
    'the copy carries the credentials the store answered with',
  );
});

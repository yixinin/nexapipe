/**
 * The node an invite brings, and the page that shows it.
 *
 * A node only reaches the Config page once it has a connection string, so the
 * page filters on that: a node in the configuration without one is not a node
 * the page can say anything about. Two things have to hold for an imported
 * node to show up — the string has to be on the node, and the page has to be
 * *told* about it.
 *
 * The second one is what this file is about. Vue only hears about a change
 * that goes through the proxy, and a node pushed into the configuration comes
 * back out of it as the raw object it was: a write to that object changes the
 * configuration without notifying anything, so the page keeps rendering the
 * list it had. An import that worked and was not shown was exactly that.
 *
 * The desktop frontend has no test runner, so this file is a plain Node
 * test, run through Vite's own SSR build — the only bundler the tree has,
 * and the one that already resolves this tree's extensionless imports. The
 * desktop CI job runs it (`npm run test:stores`), which builds each of the
 * store's test files and runs it:
 *
 *   cd ui-desktop
 *   npx vite build --ssr src/stores/config.invite.test.mjs --outDir dist-ssr
 *   node dist-ssr/config.invite.test.js
 *
 * It is a `.mjs` file because the tree has no `@types/node`: a TypeScript
 * test would fail `vue-tsc` on `node:test` before it ever ran.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computed } from 'vue';

/**
 * What the backend answers for each command.
 *
 * The store talks to the backend over the Tauri IPC, and the credentials live
 * in the store on the other side of it. An answer may be a function, which is
 * how a test observes the app at the moment a command is in flight: that is
 * when the page renders, and rendering is what has to see the new node.
 */
const answers = new Map();

/** Every command the store made, in order, with the arguments it was given. */
const calls = [];

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

const { initConfigStore, useConfigStore } = await import('./config');
const { dismissAll } = await import('../composables/useToast');

/**
 * The start-up read of the credential store.
 *
 * The mirror that writes the configuration's credentials back into the store
 * only runs once the store has answered at start-up — before that, an empty
 * credential reads as "not read back yet" rather than as "cleared". So the
 * read is done here: without it the mirror never runs, and the test about the
 * credentials the invite filed would pass for the wrong reason.
 */
answers.set('take_runtime_credentials', { relay: null, nodes: {} });
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

/**
 * The list the Config page renders.
 *
 * The same filter the page uses (`pages/ConfigPage.vue`): a node is shown when
 * it has something to connect with. It is a computed on purpose — a computed
 * is what caches, and the cache is what a change that never reaches Vue leaves
 * behind.
 */
function visibleNodes(store) {
  return computed(() =>
    store.config.nodes.filter(
      (node) => node.ticket.trim() !== '' || node.endpointId.trim() !== '',
    ),
  );
}

/** The ids the page is showing, in the order it shows them. */
function shown(list) {
  return list.value.map((node) => node.id);
}

/** A node that is already configured, as a page that has one would have. */
function existingNode(store, id, endpoint) {
  store.config.nodes.push({
    id,
    connectionType: 'endpoint_id',
    ticket: '',
    endpointId: endpoint,
    domains: [],
  });
}

/**
 * What `accept_invite` answers for an invite.
 *
 * The node id is the backend's: it names the node the credentials were filed
 * under, and the renderer cannot make that comparison any more — it no longer
 * holds the string to compare with.
 */
function acceptedInvite(nodeId, domains = []) {
  return {
    nodeId,
    connectionType: 'endpoint_id',
    existing: false,
    domains,
  };
}

/** What `take_invited_node_credentials` answers: the node's credentials. */
function storedCredentials({
  endpoint = null,
  ticket = null,
  enrollment = null,
  deviceKey = null,
} = {}) {
  return {
    totp: null,
    enrollment,
    deviceKey,
    publicKey: deviceKey ? 'aa'.repeat(32) : null,
    ticket,
    endpoint,
  };
}

test('a node imported while another one is configured is shown', async () => {
  const store = freshStore();
  existingNode(store, 'node-old', 'endpoint-old');

  const list = visibleNodes(store);
  let duringImport = [];

  answers.set('accept_invite', acceptedInvite('node-new', ['new.example']));
  answers.set('take_invited_node_credentials', async () => {
    // The page renders while the import is in flight: the node is in the
    // configuration, and its connection string has not come back yet.
    duringImport = shown(list);
    return storedCredentials({ endpoint: 'endpoint-new' });
  });

  await store.applyInvite('nexapipe://invite');

  assert.deepEqual(
    duringImport,
    ['node-old'],
    'the page had the old list while the import was in flight',
  );
  assert.deepEqual(
    shown(list),
    ['node-old', 'node-new'],
    'the imported node is shown once the import is done',
  );

  const node = store.config.nodes.find((candidate) => candidate.id === 'node-new');
  assert.ok(node, 'the node is in the configuration');
  assert.equal(node.endpointId, 'endpoint-new');
  assert.deepEqual(node.domains, ['new.example']);
});

test('the imported node shows the credentials the invite brought', async () => {
  const store = freshStore();
  existingNode(store, 'node-old', 'endpoint-old');

  // What the page renders for each node: the 2FA it answers with is part of
  // the card, and the page has rendered the old node already.
  const cards = computed(() =>
    store.config.nodes.map((node) => node.twoFactor?.clientId ?? ''),
  );
  assert.deepEqual(cards.value, ['']);

  answers.set('accept_invite', {
    ...acceptedInvite('node-new'),
    totp: { clientId: 'client-1', algorithm: 'sha1', issuer: 'nexapipe' },
  });
  answers.set('take_invited_node_credentials', storedCredentials({ endpoint: 'endpoint-new' }));

  await store.applyInvite('nexapipe://invite');

  assert.deepEqual(
    cards.value,
    ['', 'client-1'],
    'the page shows the 2FA the invite brought',
  );
});

test('a change made while the invite is being imported does not take the credential out', async () => {
  const store = freshStore();
  existingNode(store, 'node-old', 'endpoint-old');

  // Its own node id: the store is a singleton and the mirror of an earlier
  // test is still finishing its work, so the ids of the other tests are not
  // this test's business.
  answers.set('accept_invite', {
    ...acceptedInvite('node-imported'),
    enrollment: { clientId: 'client-1' },
    publicKey: 'bb'.repeat(32),
  });
  answers.set(
    'take_invited_node_credentials',
    storedCredentials({ endpoint: 'endpoint-imported', enrollment: 'token-imported' }),
  );

  const importing = store.applyInvite('nexapipe://invite');

  // The import is in flight: the backend has not answered the invite yet.
  // The change below lands between two of the import's awaits — the window
  // in which a node that is in the configuration without a connection string
  // looks exactly like a node whose credential was cleared, and a save
  // started there would take the credential the invite had just filed out
  // of the store. The store reads its credentials back *before* the node is
  // in the configuration for exactly that reason.
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(
    store.config.nodes.some((candidate) => candidate.id === 'node-imported'),
    false,
    'the import is still in flight: the change did not land between two of its awaits',
  );
  store.config.nodes[0].endpointId = 'endpoint-edited';

  await importing;

  // The save the change scheduled runs a moment after the import.
  await new Promise((resolve) => setTimeout(resolve, 700));

  const deleted = calls
    .filter((call) => call.cmd === 'delete_credential')
    .filter((call) => call.args?.nodeId === 'node-imported')
    .map((call) => call.args?.kind);

  assert.deepEqual(
    deleted.filter((kind) => kind === 'enrollment' || kind === 'endpoint' || kind === 'devicekey'),
    [],
    'the credential the invite filed is still in the store',
  );
});

test('the credential the invite filed stays in the store', async () => {
  const store = freshStore();
  existingNode(store, 'node-old', 'endpoint-old');

  // A machine with no device name yet: asking for one writes the configuration,
  // and that save is what would see a node with no enrollment on it.
  store.config.deviceId = '';

  answers.set('accept_invite', {
    ...acceptedInvite('node-new'),
    enrollment: { clientId: 'client-1' },
    publicKey: 'bb'.repeat(32),
  });
  answers.set(
    'take_invited_node_credentials',
    storedCredentials({
      endpoint: 'endpoint-new',
      enrollment: 'token-1',
      deviceKey: 'cc'.repeat(32),
    }),
  );

  await store.applyInvite('nexapipe://invite');

  // The save is debounced, so the mirror that writes the credentials runs a
  // moment after the import is done.
  await new Promise((resolve) => setTimeout(resolve, 700));

  const deleted = calls
    .filter((call) => call.cmd === 'delete_credential')
    .filter((call) => call.args?.nodeId === 'node-new')
    .map((call) => call.args?.kind);

  assert.deepEqual(
    deleted.filter((kind) => kind === 'enrollment' || kind === 'endpoint' || kind === 'devicekey'),
    [],
    'the credentials the invite filed are still in the store',
  );

  // And they are in the store because the mirror wrote them. "Nothing was
  // deleted" is not enough on its own: a mirror that deleted nothing and
  // wrote nothing either would leave the node with no credential at all, and
  // the assertion above would not have noticed.
  const written = calls
    .filter((call) => call.cmd === 'put_credential')
    .filter((call) => call.args?.nodeId === 'node-new')
    .map((call) => ({ kind: call.args?.kind, value: call.args?.value }));

  assert.ok(
    written.some((entry) => entry.kind === 'enrollment' && entry.value === 'token-1'),
    'the enrollment token the invite filed is in the store',
  );
  assert.ok(
    written.some((entry) => entry.kind === 'endpoint' && entry.value === 'endpoint-new'),
    'the connection string the invite filed is in the store',
  );
  // The device key is the backend's: the renderer writes it back never and
  // takes it out never, so what is in the store is the one the invite filed.
  assert.deepEqual(
    written.filter((entry) => entry.kind === 'devicekey'),
    [],
    'the device key is the backend\'s: the renderer does not write it',
  );
});

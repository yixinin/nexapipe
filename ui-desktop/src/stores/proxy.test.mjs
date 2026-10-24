/**
 * The service gate, and what a read that does not come back may decide.
 *
 * The desktop frontend has no test runner, so this file is a plain Node
 * test, run through Vite's own SSR build — the only bundler the tree has,
 * and the one that already resolves this tree's extensionless imports. The
 * desktop CI job runs it (`npm run test:stores`), which builds each of the
 * store's test files and runs it:
 *
 *   npx vite build --ssr src/stores/proxy.test.mjs --outDir dist-ssr --logLevel error
 *   node dist-ssr/proxy.test.js
 *
 * The service is asked three questions together: whether something answers on
 * the IPC port, what the platform's service manager says about the service,
 * and which build the service claims. The IPC read has deadlines of its own —
 * half a second to connect and five to be answered — and a busy machine
 * misses them while the service is alive and well.
 *
 * One missed deadline is not a fact about the service. Believing it turns TUN
 * off, loses the setting across the next launch, and raises the drift banner
 * that offers to reinstall a service that was never broken. Several misses in
 * a row are a fact.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

/** What the backend answers for each command. */
const answers = new Map();

/**
 * The browser globals the store expects.
 *
 * `localStorage` holds the configuration payload, and `window.__TAURI_INTERNALS__` is where
 * Tauri's `invoke` sends every command.
 */
globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
};

globalThis.window = {
  __TAURI_INTERNALS__: {
    invoke: async (cmd, args) => {
      const answer = answers.get(cmd);
      if (typeof answer === 'function') return await answer(args);
      return answer === undefined ? null : answer;
    },
  },
};

const { useProxyStore } = await import('./proxy');
const { useConfigStore } = await import('./config');
const { useToast } = await import('../composables/useToast');

/**
 * How many consecutive failed reads the store requires before it acts on them.
 *
 * Pinned here on purpose: the point of the change is that one missed deadline is not a fact
 * about the service, and that the count is what turns repeated misses into one.
 */
const FAILURES = 3;

/**
 * A store with a TUN request on it and nothing said about it yet.
 *
 * The count of the reads that did not answer lives in the module, so a test
 * that starts from a known count says so: one read that answers clears it.
 */
async function freshStore() {
  const { config, updateConfig } = useConfigStore();
  updateConfig({ useTun: true });
  assert.equal(config.useTun, true, 'the store starts with a TUN request');
  useToast().dismissAll();
  const store = useProxyStore();
  serviceHealthy();
  await store.refreshServiceRunning();
  useToast().dismissAll();
  return store;
}

/** The service manager says the service is up; the IPC port does not answer. */
function serviceUpButSilent() {
  answers.set('get_service_status', 'running');
  answers.set('is_service_running', false);
  answers.set('get_service_version', null);
}

/** Everything answers: the service is up and speaking this build. */
function serviceHealthy() {
  answers.set('get_service_status', 'running');
  answers.set('is_service_running', true);
  answers.set('get_service_version', '1.0.0');
}

/** The service manager says the service is stopped. */
function serviceStopped() {
  answers.set('get_service_status', 'stopped');
  answers.set('is_service_running', false);
  answers.set('get_service_version', null);
}

/** The service manager says the service is not installed. */
function serviceNotInstalled() {
  answers.set('get_service_status', 'not_installed');
  answers.set('is_service_running', false);
  answers.set('get_service_version', null);
}

test('one missed deadline keeps the TUN request, says nothing, and claims no drift', async () => {
  const store = await freshStore();
  serviceUpButSilent();

  await store.refreshServiceRunning();

  const { config } = useConfigStore();
  assert.equal(
    config.useTun,
    true,
    'the TUN request survives a read that did not answer: one missed deadline is not a fact ' +
      'about the service, and losing it would silently run the local proxy on the next launch',
  );
  assert.equal(
    useToast().toasts.value.length,
    0,
    'nothing is said about a service that did not answer this time',
  );
  assert.equal(
    store.serviceStale.value,
    false,
    'no drift is claimed from one missed deadline: the drift banner invites a reinstall of a ' +
      'service that was never broken',
  );
});

test('a read that answers clears the count of the ones that did not', async () => {
  const store = await freshStore();
  serviceUpButSilent();

  await store.refreshServiceRunning();
  await store.refreshServiceRunning();
  assert.equal(config().useTun, true, 'the TUN request is still standing');

  serviceHealthy();
  await store.refreshServiceRunning();
  assert.equal(store.serviceRunning.value, true, 'the service answered');

  // Two misses again: the count started from zero, so nothing is believed yet.
  serviceUpButSilent();
  await store.refreshServiceRunning();
  await store.refreshServiceRunning();
  assert.equal(
    config().useTun,
    true,
    'the misses before the good read do not count towards the ones after it',
  );
});

test('a service that has really stopped answering turns TUN off, says so, and raises the drift', async () => {
  const store = await freshStore();
  serviceUpButSilent();

  for (let i = 0; i < FAILURES; i++) {
    await store.refreshServiceRunning();
  }

  assert.equal(
    config().useTun,
    false,
    'a service that has stopped answering for good takes the TUN request with it',
  );
  assert.equal(
    useToast().toasts.value.length,
    1,
    'the user is told why the TUN request was dropped',
  );
  assert.equal(
    store.serviceStale.value,
    true,
    'the drift banner is raised: the service manager says the service is running and it did ' +
      'not answer which build it is',
  );
});

test('a service the manager says is not installed is taken at once', async () => {
  const store = await freshStore();
  serviceNotInstalled();

  await store.refreshServiceRunning();

  assert.equal(
    config().useTun,
    false,
    'the service manager reads the platform locally and has no deadline a busy machine can ' +
      'miss: a service it says is not installed is gone for certain, and the TUN request goes ' +
      'with it at once',
  );
  assert.equal(
    useToast().toasts.value.length,
    1,
    'the user is told why the TUN request was dropped',
  );
  assert.equal(
    store.serviceStale.value,
    false,
    'a service that is not installed is not an outdated one: the drift banner would offer to ' +
      'reinstall a service that is not there',
  );
});

test('a service that is stopped turns TUN off without claiming an outdated build', async () => {
  const store = await freshStore();
  serviceStopped();

  for (let i = 0; i < FAILURES; i++) {
    await store.refreshServiceRunning();
  }

  assert.equal(config().useTun, false, 'a stopped service takes the TUN request with it');
  assert.equal(
    store.serviceStale.value,
    false,
    'a stopped service is not an outdated one: the drift banner would offer a reinstall for a ' +
      'service that is not running',
  );
});

/** The configuration, read the way a caller reads it. */
function config() {
  return useConfigStore().config;
}

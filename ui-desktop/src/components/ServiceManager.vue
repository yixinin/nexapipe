<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { useI18n } from "vue-i18n";
import { errorDetail, errorKey } from "../api/errors";
import type { ServiceState } from "../types";
import { useProxyStore } from "../stores/proxy";

const { t } = useI18n();

// Installing here changes whether the Connect page may offer TUN, and that gate lives in the
// proxy store. Nothing else refreshes it, so without this the TUN toggle stays switched off —
// and its "install service" button stays on screen — until the app is restarted.
// The same store also answers the question this panel cannot ask the service manager: whether
// something is *answering* on the IPC port. A registered service is up as far as the OS is
// concerned well before it listens, and a service that never answers anything cannot be read as
// one that is out of date.
const { refreshServiceRunning, settleService, serviceRunning } = useProxyStore();

const state = ref<ServiceState>("not_installed");
const isLoading = ref(false);
const busyWith = ref<"" | "install" | "upgrade" | "uninstall" | "start" | "stop" | "restart">("");
const message = ref("");
const messageType = ref<"success" | "error" | "info">("info");

/// This build, which is what the service is compared against. Empty until the app has said,
/// and a comparison against nothing is one the panel does not draw.
const appVersion = ref("");
/// Which build the service says it is, once something on the IPC port is answering. `null` when
/// that answer did not come back — either nothing was reachable, which [`serviceRunning`] has
/// already ruled out by then, or the service predates the question and closes the connection
/// instead, which is the case the notice is for.
const serviceVersion = ref<string | null>(null);

/// Which build the service was *installed* from, read from the record the install wrote.
///
/// The answer the service itself gives is the better one, but it needs the IPC to work — and
/// the case this is for is the one where it does not: a service left behind by an upgrade
/// keeps running while the app has been replaced, and the two no longer speak the same
/// protocol. The record is on disk (or in the registry) either way, so the panel can still
/// say which build is out there.
const installedVersion = ref<string | null>(null);

/**
 * The timer that takes a success message off the screen.
 *
 * A failure is not on a timer at all: it stays until the next action replaces it. It is the
 * only thing that says why the panel did not change, and a message that disappears after
 * three seconds is a message nobody reads — which is exactly what an uninstall that left the
 * service registered looked like.
 */
let messageTimer: number | undefined;

function clearMessageTimer() {
  if (messageTimer !== undefined) {
    window.clearTimeout(messageTimer);
    messageTimer = undefined;
  }
}

/// A service can die on its own, so the panel re-reads the state instead of trusting the last
/// action it performed.
const POLL_INTERVAL_MS = 10_000;
let poll: number | undefined;

/// Spelled out rather than built from the state string, so the keys stay statically visible.
const stateLabel = computed(() => {
  switch (state.value) {
    case "running":
      return t("service.stateRunning");
    case "stopped":
      return t("service.stateStopped");
    default:
      return t("service.stateNotInstalled");
  }
});

async function refresh() {
  try {
    state.value = await invoke<ServiceState>("get_service_status");
  } catch (e) {
    console.error("[service] failed to read the service state:", errorDetail(e));
    state.value = "not_installed";
  }

  try {
    serviceVersion.value = await invoke<string | null>("get_service_version");
  } catch (e) {
    console.error("[service] failed to read the service version:", errorDetail(e));
    serviceVersion.value = null;
  }

  try {
    installedVersion.value = await invoke<string | null>("get_service_installed_version");
  } catch (e) {
    console.error("[service] failed to read the installed service version:", errorDetail(e));
    installedVersion.value = null;
  }
}

/// The service is up and said which build it is, and that build is not this app's. The single
/// drift that reinstalling actually fixes, and the only one worth a banner.
///
/// Pre-PR # this was conflated with [`versionUnknown`] — `null !== "0.5.0"` is true, so a service
/// that simply hadn't answered was reported as drift. That conflation was platform-agnostic but
/// hit macOS / Linux first when the desktop's webview ACL refused the version query (PR #100),
/// and it would still bite whenever the daemon's IPC handshake is older than the question.
const versionMismatch = computed(
  () =>
    appVersion.value !== "" &&
    serviceRunning.value &&
    serviceVersion.value !== null &&
    serviceVersion.value !== appVersion.value,
);

/// The service is up but did not answer which build it is. A build that predates the question
/// closes the connection instead of answering it (and on macOS / Linux, anything that prevents
/// the IPC client from getting a version through `IpcClient::get_version` lands here too). The
/// action is the same as a mismatch (reinstall this app's build), but the wording has to make
/// clear that an unknown build is not the same as a known-outdated one — otherwise a user with
/// both an old service and a working one would reinstall the wrong machine.
///
/// Drawn as its own computed so the [`needsUpgradeMessage`] can branch on it and the future-
/// debugging surface stays one boolean away.
const versionUnknown = computed(
  () =>
    appVersion.value !== "" &&
    // The manager still has to say running: a service that has stopped and left a version read
    // that failed is down, which is not the same reading as an outdated one.
    state.value === "running" &&
    serviceRunning.value &&
    serviceVersion.value === null,
);

/// The build the service was installed from is not this build.
///
/// The comparison the panel cannot make any other way once the IPC is down: the service that
/// cannot answer is exactly the one whose version has to be read from the record the install
/// left behind.
///
/// The record says which build was *registered*, and it is the right answer only when the
/// service cannot speak for itself: a service that is answering has already said which build
/// it is, and a record left behind by a service that was removed out of band asserts a drift
/// on a machine that has no service at all.
const installedVersionMismatch = computed(
  () =>
    state.value !== "not_installed" &&
    !serviceRunning.value &&
    appVersion.value !== "" &&
    installedVersion.value !== null &&
    installedVersion.value !== appVersion.value,
);

/// The service manager says the service is running, and nothing is answering on the IPC.
///
/// Two facts from two places, which only coincide when the service is the build this app
/// expects. A service left behind by an upgrade keeps running — the job is fine, the
/// protocol is not — and this is the one signal that says so without the service having to
/// answer anything.
const serviceUnreachable = computed(
  () => state.value === "running" && !serviceRunning.value,
);

/// Any drift state warrants the banner; the wording is what tells them apart.
///
/// This decides which action the row below offers, so it stays true for as long as the drift
/// lasts: hiding the banner mid-action must not bring the install button back while that
/// button would be a different action's.
const needsUpgrade = computed(
  () =>
    versionMismatch.value ||
    versionUnknown.value ||
    installedVersionMismatch.value ||
    serviceUnreachable.value,
);

/// Whether the banner is drawn.
///
/// Not while an action is in flight: its settle re-reads the two service facts at different
/// moments than this panel re-reads its own, and drawing them in between is what showed a
/// healthy stop as a service that does not answer. A genuine drift is still on screen the
/// moment the action is over, because by then every reading has been taken again.
const bannerVisible = computed(() => !isLoading.value && needsUpgrade.value);

const needsUpgradeMessage = computed(() => {
  // On the *mismatch*, not on any answer: a service that reported this app's own build is
  // not a mismatch, and saying so with the same string on both sides reads as nonsense.
  if (versionMismatch.value) {
    return t("service.versionMismatch", { service: serviceVersion.value, app: appVersion.value });
  }
  if (installedVersionMismatch.value) {
    return t("service.installedVersionMismatch", {
      service: installedVersion.value,
      app: appVersion.value,
    });
  }
  if (serviceUnreachable.value) {
    return t("service.notAnswering");
  }
  return t("service.versionUnknown", { app: appVersion.value });
});

/// What the install button says: putting a service on the machine, or replacing the one that
/// is on it.
///
/// Replacing it is a *reinstall*: a service with drift gets the banner above, and that banner
/// carries the upgrade action itself, so a visible install button means the panel found no
/// drift to report. Calling the same command an upgrade there would claim one was available.
const installLabel = computed(() =>
  state.value === "not_installed" ? t("service.install") : t("service.reinstall"),
);

/**
 * Every one of these elevates through UAC / sudo / polkit when the process is not already
 * privileged, so the call can legitimately stay pending until the user answers the prompt.
 */
async function run(
  action: "install" | "upgrade" | "uninstall" | "start" | "stop" | "restart",
  command: string,
  successKey: string,
  fallbackKey: string,
) {
  if (isLoading.value) return;

  // Whatever the previous action said goes away with it: a message still on screen while the
  // next attempt runs describes an attempt that is over.
  clearMessageTimer();
  message.value = "";

  isLoading.value = true;
  busyWith.value = action;

  let succeeded = false;
  let settled = true;
  try {
    await invoke<void>(command);
    succeeded = true;
  } catch (e) {
    message.value = t(errorKey(e, fallbackKey));
    messageType.value = "error";
    console.error(`[service] ${action} failed:`, errorDetail(e) || e);
  } finally {
    if (succeeded) {
      // The action is over when the service manager accepted it, not when the service speaks
      // again. Reading right here is what drew a healthy restart or stop as drift for a moment:
      // the manager already said "running" or "stopped" while the IPC was still catching up, so
      // a version read that failed in that window was paired with a stale "running". Each action
      // names the pair it is heading towards, and both answers are read only once it is reached.
      // A target that is never reached is reported below rather than counted as success.
      settled = await settleService(
        action === "stop" ? "quiet" : action === "uninstall" ? "absent" : "answering",
      );
    } else {
      // Nothing settled: whatever the failed action left behind is the state to show.
      await refreshServiceRunning();
    }
    // Re-read even after a failure: an install that could not start the service, or an
    // uninstall that was refused, still leaves something behind to show. The versions are read
    // after the service facts above, because the banner compares them against `serviceRunning`.
    await refresh();
    // Said after the settle: a command whose effect never showed up is not a success, even
    // though the service manager accepted it.
    if (succeeded) {
      message.value = settled ? t(successKey) : t("service.notSettled");
      messageType.value = settled ? "success" : "error";
    }
    isLoading.value = false;
    busyWith.value = "";
    // Only a success is on a timer. A failure waits for the next action to replace it.
    if (messageType.value === "success") {
      messageTimer = window.setTimeout(() => {
        message.value = "";
        messageTimer = undefined;
      }, 3000);
    }
  }
}

function installService() {
  // The same command either way: an install re-points the service at this build and
  // restarts it. What the panel says afterwards depends on what it found — a service that
  // was not there, or one that is being replaced.
  const successKey =
    state.value === "not_installed" ? "service.installed" : "service.reinstalled";
  return run("install", "install_service", successKey, "error.service.install_failed");
}

/// Reinstalling *is* the upgrade: installing re-points the service at this build and restarts
/// it, so a service left behind by an earlier version of the app ends up running this one.
function upgradeService() {
  return run("upgrade", "install_service", "service.upgraded", "error.service.install_failed");
}

function uninstallService() {
  return run("uninstall", "uninstall_service", "service.uninstalled", "error.service.uninstall_failed");
}

function startService() {
  return run("start", "start_service", "service.started", "error.service.start_failed");
}

function stopService() {
  return run("stop", "stop_service", "service.stopped", "error.service.stop_failed");
}

function restartService() {
  return run("restart", "restart_service", "service.restarted", "error.service.restart_failed");
}

onMounted(() => {
  // Read once: it is this build's own version, and outside a Tauri window there is none — in
  // which case the panel simply stops drawing the comparison.
  void getVersion()
    .then((value) => {
      appVersion.value = value;
    })
    .catch((e) => console.debug("[service] app version unavailable:", e));

  refresh();
  poll = window.setInterval(() => {
    // An action in flight owns the state read: a poll landing mid-transition would see one
    // answer changed and the other not, which is the drift the settle exists to avoid.
    if (!isLoading.value) void refresh();
  }, POLL_INTERVAL_MS);
});

onBeforeUnmount(() => {
  if (poll !== undefined) window.clearInterval(poll);
  clearMessageTimer();
});
</script>

<template>
  <div class="service-manager">
    <div class="card-header">
      <h2>{{ t("service.title") }}</h2>
      <div class="card-header-decoration"></div>
    </div>
    
    <div class="service-status">
      <div class="status-row">
        <div class="status-left">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
          <span class="status-label">{{ t("service.status") }}</span>
        </div>
        <div class="status-right">
          <span class="status-value" :class="state">
            <span class="status-dot"></span>
            {{ stateLabel }}
          </span>
        </div>
      </div>
    </div>

    <div v-if="bannerVisible" class="outdated">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      </svg>
      <div class="outdated-body">
        <span>{{ needsUpgradeMessage }}</span>
        <button
          class="btn btn-outline"
          :disabled="isLoading"
          @click="upgradeService"
        >
          <svg v-if="busyWith === 'upgrade'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
          </svg>
          <span>{{ t("service.upgrade") }}</span>
        </button>
      </div>
    </div>

    <div v-if="message" class="message" :class="messageType">
      <svg v-if="messageType === 'success'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
      <svg v-else-if="messageType === 'error'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="16" x2="12" y2="12"/>
        <line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg>
      <span>{{ message }}</span>
    </div>

    <!--
      The spinner reports the work; the labels do not change. A busy label a few characters
      longer than its idle one widened the row while it ran, which pushed the last button onto
      a line of its own for the duration of the action.
    -->
    <div class="service-actions">
      <!--
        Hidden while the notice above is up: that one carries the same action, and two
        buttons that do the same thing under the same label are one too many. The notice is
        also hidden while its action runs, which is why the upgrade is repeated here for that
        time: without it the only progress indicator would go away with the notice.
      -->
      <button
        v-if="!needsUpgrade && busyWith !== 'upgrade'"
        class="btn btn-outline"
        :disabled="isLoading"
        @click="installService"
      >
        <svg v-if="busyWith === 'install'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else-if="state === 'not_installed'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 5v14"/>
          <path d="M5 12h14"/>
        </svg>
        <svg v-else class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 4v5h5"/>
          <path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 20v-5h-5"/>
        </svg>
        <span>{{ installLabel }}</span>
      </button>
      <button
        v-else-if="busyWith === 'upgrade'"
        class="btn btn-outline"
        disabled
      >
        <svg class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <span>{{ t("service.upgrade") }}</span>
      </button>

      <button
        class="btn btn-outline"
        :disabled="isLoading || state !== 'stopped'"
        @click="startService"
      >
        <svg v-if="busyWith === 'start'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        <span>{{ t("service.start") }}</span>
      </button>

      <button
        class="btn btn-outline"
        :disabled="isLoading || state !== 'running'"
        @click="stopService"
      >
        <svg v-if="busyWith === 'stop'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="6" y="6" width="12" height="12" rx="1"/>
        </svg>
        <span>{{ t("service.stop") }}</span>
      </button>

      <button
        class="btn btn-outline"
        :disabled="isLoading || state !== 'running'"
        @click="restartService"
      >
        <svg v-if="busyWith === 'restart'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 4v5h5"/>
          <path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 20v-5h-5"/>
        </svg>
        <span>{{ t("service.restart") }}</span>
      </button>

      <button
        class="btn btn-outline btn-danger"
        :disabled="isLoading || state === 'not_installed'"
        @click="uninstallService"
      >
        <svg v-if="busyWith === 'uninstall'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
        <span>{{ t("service.uninstall") }}</span>
      </button>
    </div>

    <div class="service-hints">
      <div class="hint-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
        </svg>
        <span>{{ t("service.hintElevation") }}</span>
      </div>
      <div class="hint-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 8v4l3 3"/>
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <span>{{ t("service.hintAutostart") }}</span>
      </div>
      <div class="hint-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <span>{{ t("service.hintProduction") }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.service-manager {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 28px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-header-decoration {
  flex: 1;
  height: 3px;
  background: var(--gradient-primary);
  border-radius: 2px;
}

.service-status {
  background: var(--surface-2);
  border-radius: var(--radius-md);
  padding: 18px 20px;
  margin-bottom: 16px;
  border: 1px solid var(--border-light);
}

.status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.status-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-left svg {
  width: 18px;
  height: 18px;
  color: var(--text-muted);
}

.status-label {
  font-size: 14px;
  color: var(--text-secondary);
  font-weight: 500;
}

.status-right {
  display: flex;
  align-items: center;
}

.status-value {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 14px;
  transition: all var(--transition-normal);
}

.status-value.running {
  color: var(--success-600);
  background: var(--success-50);
  border: 1px solid var(--success-200);
}

.status-value.stopped {
  color: var(--text-muted);
  background: var(--surface-3);
  border: 1px solid var(--border-color);
}

.status-value.not_installed {
  color: var(--text-muted);
  background: var(--surface-2);
  border: 1px dashed var(--border-color);
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.status-value.running .status-dot {
  background: var(--success-500);
  animation: pulse 2s ease-in-out infinite;
}

.status-value.stopped .status-dot,
.status-value.not_installed .status-dot {
  background: var(--text-muted);
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

.outdated {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 14px;
  border-radius: var(--radius-md);
  margin-bottom: 16px;
  font-size: 13px;
  background: var(--warning-subtle);
  color: var(--warning-text);
  border-left: 3px solid var(--warning);
}

.outdated svg {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 2px;
}

.outdated-body {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
}

.outdated-body .btn {
  padding: 8px 14px;
  font-size: 13px;
  border-color: var(--warning);
  color: var(--warning-text);
}

.outdated-body .btn:hover:not(:disabled) {
  background: var(--warning-subtle);
}

.message {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px;
  border-radius: var(--radius-md);
  margin-bottom: 16px;
  font-size: 13px;
  transition: all var(--transition-normal);
}

.message svg {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.message.success {
  background: var(--success-50);
  color: var(--success-700);
  border-left: 3px solid var(--success-500);
}

.message.error {
  background: var(--error-50);
  color: var(--error-700);
  border-left: 3px solid var(--error-500);
}

.message.info {
  background: var(--primary-50);
  color: var(--primary-700);
  border-left: 3px solid var(--primary-500);
}

.service-actions {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  border-radius: var(--radius-md);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
}

.btn svg {
  width: 16px;
  height: 16px;
}

.btn-outline {
  background: transparent;
  border: 1.5px solid var(--border-color);
  color: var(--text-secondary);
}

.btn-outline:hover:not(:disabled) {
  background: var(--surface-2);
  border-color: var(--primary-400);
  color: var(--primary-600);
}

.btn-outline.btn-danger {
  border-color: var(--error-300);
  color: var(--error-600);
}

.btn-outline.btn-danger:hover:not(:disabled) {
  background: var(--error-50);
  border-color: var(--error-500);
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

/* A spinner reports an operation in flight, so the global reduced-motion stop
   in base.css is answered here the same way as in AppButton.vue. */
@media (prefers-reduced-motion: reduce) {
  .spinner {
    animation-duration: 1s !important;
    animation-iteration-count: infinite !important;
  }
}

.service-hints {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.hint-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  background: var(--surface-2);
  border-radius: var(--radius-sm);
}

.hint-item svg {
  width: 14px;
  height: 14px;
  color: var(--text-muted);
  flex-shrink: 0;
  margin-top: 2px;
}

.hint-item span {
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.4;
}

@media (max-width: 480px) {
  .service-actions {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
    justify-content: center;
  }
}
</style>
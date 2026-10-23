<script setup lang="ts">
/**
 * The Connect page's status panel: what the proxy is doing right now, the one control that
 * changes it, and the forwarding-mode switch.
 *
 * It renders state and nothing else. Every `invoke()` lives in `stores/proxy.ts`, which also owns
 * the poll that keeps this panel current — hence no refresh button: the status, the node ID and
 * every node's link kind are re-read on a timer, so a service that dies, or a path iroh promotes
 * from relay to direct, shows up on its own (§3.3).
 *
 * The switch is an explicit request, never a probe: TUN is gated on the service being installed,
 * and when it cannot be honoured the backend fails with `proxy.tun_unavailable` instead of
 * quietly forwarding traffic another way (docs/ui-refactor-plan.md §5.12).
 */
import { computed, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { invoke } from '@tauri-apps/api/core';
import AppButton from './base/AppButton.vue';
import AppIcon from './base/AppIcon.vue';
import AppToggle from './base/AppToggle.vue';
import { errorKey } from '../api/errors';
import { confirm } from '../composables/useConfirm';
import { useToast } from '../composables/useToast';
import { writeClipboardText } from '../utils/clipboard';
import { formatBytes, formatRate } from '../utils/format';
import { useConfigStore } from '../stores/config';
import { useCredentialGate } from '../stores/gate';
import { useProxyStore } from '../stores/proxy';
import type { LinkKind } from '../types';

const { t } = useI18n();
const toast = useToast();

const { config } = useConfigStore();
const {
  status,
  nodeId,
  busy,
  startupError,
  serviceRunning,
  serviceInstalled,
  endpointLinks,
  stale,
  canStart,
  totals,
  rate,
  start,
  stop,
  refreshServiceRunning,
  revealNodeId,
  setUseTun,
} = useProxyStore();

const { ensureUnlocked } = useCredentialGate();

const installing = ref(false);

const modeLabel = computed(() => {
  if (status.value.running) return t(`mode.${status.value.mode}`);
  // The state could not be read, which is not the same as stopped: the service owns the
  // tunnel and this process cannot see it. Saying "stopped" would be a guess.
  if (status.value.mode === 'unknown') return t('status.unknown');
  return t('status.stopped');
});

const statusLabel = computed(() => {
  if (status.value.running) return t('status.running');
  if (status.value.mode === 'starting') return t('status.starting');
  return t('status.stopped');
});

/** The failure `start_proxy` recorded after it had already returned, if any. */
const startupMessage = computed(() =>
  startupError.value ? t(errorKey(startupError.value, 'error.proxy.start_failed')) : '',
);

/**
 * What the link indicator shows: the kind of path traffic is *actually* taking, not the relay
 * mode from the configuration. Null when no node has reported a path yet, so nothing is claimed.
 */
const linkInfo = computed(() => {
  const kinds: LinkKind[] = endpointLinks.value
    .map((link) => link.link)
    .filter((kind) => kind !== 'unknown');
  if (kinds.length === 0) return null;

  const direct = kinds.filter((kind) => kind === 'direct').length;
  if (direct === kinds.length) return { label: 'Direct', icon: 'link-direct', tone: 'direct' };
  if (direct === 0) return { label: 'Relay', icon: 'link-relay', tone: 'relay' };
  return { label: 'Mixed', icon: 'link-relay', tone: 'mixed' };
});

const tunHint = computed(() =>
  serviceRunning.value ? t('connect.tunHint') : t('connect.tunRequiresService'),
);

/**
 * Flipping the mode while the proxy is up is a restart, not a toggle: the backend only reads
 * `use_tun` when it starts. Asking first is the difference between "the tunnel blinked" and
 * "the tunnel blinked and I do not know why".
 */
async function setTun(enabled: boolean): Promise<void> {
  if (enabled && !serviceRunning.value) {
    toast.warning(t('connect.tunRequiresService'));
    return;
  }

  if (!status.value.running) {
    setUseTun(enabled);
    return;
  }

  const ok = await confirm({
    title: t('connect.tunRestartTitle'),
    message: t('connect.tunRestartMessage', {
      mode: enabled ? t('mode.tun') : t('mode.local_proxy'),
    }),
    tone: 'warning',
  });
  if (!ok) return;

  setUseTun(enabled);
  await stop();
  await start();
}

/** Bound to the switch: `AppToggle` is controlled, so a refused change has to be swallowed here. */
const tunModel = computed({
  get: () => config.useTun,
  set: (enabled: boolean) => {
    void setTun(enabled);
  },
});

/**
 * Installing the service from here rather than sending the user to Settings: the switch they
 * just tried to flip is the thing that needs it, and the elevation prompt explains itself.
 */
async function installServiceForTun(): Promise<void> {
  const ok = await confirm({
    title: t('connect.tunInstallTitle'),
    message: t('connect.tunInstallMessage'),
  });
  if (!ok) return;

  installing.value = true;
  try {
    await invoke<void>('install_service');
    await refreshServiceRunning();
    toast.success(t('service.installed'));
  } catch (error) {
    toast.error(error, 'error.service.install_failed');
  } finally {
    installing.value = false;
  }
}

/**
 * Copies the Node ID, which means asking for it: `nodeId` is a mask, and what goes on the
 * clipboard has to be the whole string. Copying is the act that makes the full value worth
 * having, so it is also the act the OS lock will sit in front of.
 */
async function copyNodeId(): Promise<void> {
  if (!nodeId.value) return;
  // The Node ID is the name this machine answers to on the network, so copying
  // it is worth the same question as copying a credential.
  if (!(await ensureUnlocked(t('gate.reasonNodeId')))) return;
  const full = await revealNodeId();
  if (!full) {
    // Nothing was fetched, so nothing was copied. A clipboard failure this is
    // not, and saying "could not copy" sends the user looking at the wrong
    // thing: the value never arrived.
    toast.error(t('connect.nodeIdUnavailable'));
    return;
  }
  if (await writeClipboardText(full)) {
    toast.success(t('common.copied'));
  } else {
    toast.error(t('common.copyFailed'));
  }
}
</script>

<template>
  <div class="proxy-status">
    <div class="proxy-status__main">
      <span
        class="proxy-status__ring"
        :class="{ running: status.running, starting: status.mode === 'starting' }"
        aria-hidden="true"
      >
        <span class="proxy-status__dot" />
      </span>

      <div class="proxy-status__text">
        <span class="proxy-status__title">{{ statusLabel }}</span>
        <span class="proxy-status__subtitle">{{ modeLabel }}</span>
      </div>

      <div class="proxy-status__actions">
        <AppButton
          v-if="!status.running"
          tone="primary"
          icon="play"
          :loading="busy"
          :disabled="!canStart"
          @click="start()"
        >
          {{ t('connect.start') }}
        </AppButton>
        <AppButton v-else tone="danger" icon="stop" :loading="busy" @click="stop()">
          {{ t('connect.stop') }}
        </AppButton>
      </div>
    </div>

    <div v-if="status.running" class="proxy-status__pills">
      <span class="pill pill--mode">{{ modeLabel }}</span>
      <span v-if="linkInfo" class="pill" :class="`pill--${linkInfo.tone}`">
        <AppIcon :name="linkInfo.icon" :size="14" />
        {{ linkInfo.label }}
      </span>
    </div>

    <!--
      What the tunnel has carried in total, and how fast it is carrying it right now.

      Only while there is something to add up: `totals` is null until the counters have been read,
      and "not read yet" is not the same as "read, and the answer is zero" — a row of zeroes drawn
      before the first byte moved reads as a tunnel that connects and forwards nothing.

      The rate is its own condition because it needs two readings, not one: the first poll of a
      run has nothing to divide against, and saying `0 B/s` then is the same lie in the other
      direction.
    -->
    <div v-if="totals" class="proxy-status__traffic">
      <span class="traffic-figure traffic-figure--sent">
        <AppIcon name="arrow-up" :size="13" />
        <span class="traffic-figure__label">{{ t('traffic.totalSent') }}</span>
        <span class="traffic-figure__value">{{ formatBytes(totals.sent) }}</span>
        <span v-if="rate" class="traffic-figure__rate">{{ formatRate(rate.up) }}</span>
      </span>

      <span class="traffic-figure traffic-figure--received">
        <AppIcon name="arrow-down" :size="13" />
        <span class="traffic-figure__label">{{ t('traffic.totalReceived') }}</span>
        <span class="traffic-figure__value">{{ formatBytes(totals.received) }}</span>
        <span v-if="rate" class="traffic-figure__rate">{{ formatRate(rate.down) }}</span>
      </span>

      <span class="pill pill--flows">{{ t('traffic.flows', { count: totals.active }) }}</span>
    </div>

    <div v-if="nodeId" class="proxy-status__node">
      <span class="proxy-status__label">{{ t('connect.nodeId') }}</span>
      <code class="proxy-status__value">{{ nodeId }}</code>
      <button
        type="button"
        class="proxy-status__copy"
        :aria-label="t('common.copy')"
        @click="copyNodeId"
      >
        <AppIcon name="copy" :size="16" />
      </button>
    </div>

    <div class="proxy-status__tun">
      <div class="proxy-status__tun-text">
        <span class="proxy-status__tun-label">{{ t('connect.tunToggle') }}</span>
        <span class="proxy-status__tun-hint">{{ tunHint }}</span>
      </div>

      <AppButton
        v-if="!serviceInstalled"
        size="sm"
        tone="ghost"
        :loading="installing"
        @click="installServiceForTun"
      >
        {{ t('service.install') }}
      </AppButton>

      <AppToggle v-model="tunModel" :disabled="!serviceRunning" :label="t('connect.tunToggle')" />
    </div>

    <p v-if="startupMessage" class="proxy-status__error">{{ startupMessage }}</p>

    <p v-if="stale" class="proxy-status__stale">{{ t('connect.stale') }}</p>
  </div>
</template>

<style scoped>
.proxy-status {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.proxy-status__main {
  display: flex;
  align-items: center;
  gap: var(--space-4);
}

.proxy-status__ring {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  border: 3px solid var(--border-default);
  border-radius: 50%;
  flex-shrink: 0;
  transition: border-color var(--duration-fast) var(--ease-standard);
}

.proxy-status__ring.running {
  border-color: var(--success);
}

.proxy-status__ring.starting {
  border-color: var(--accent);
}

.proxy-status__dot {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--text-muted);
  transition: background-color var(--duration-fast) var(--ease-standard);
}

.proxy-status__ring.running .proxy-status__dot {
  background: var(--success);
  box-shadow: 0 0 12px var(--success);
}

.proxy-status__ring.starting .proxy-status__dot {
  background: var(--accent);
  /* Promoted to its own layer, for the same reason as the button spinner in
     AppButton.vue: a dot whose scale and opacity are recalculated by the main
     thread is the first thing to stall once the status poll re-renders the
     panel around it, which leaves a starting indicator that sits still. */
  will-change: transform, opacity;
  animation: proxy-status-pulse 1.5s ease-in-out infinite;
}

@keyframes proxy-status-pulse {
  0%,
  100% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.2);
    opacity: 0.7;
  }
}

/* What "still working" looks like when the surroundings must not move. Scaling
   is the part Reduce Motion exists to suppress, so this swaps in a breath that
   changes nothing but opacity: no size, no position, no reflow of the ring
   around it, and still visibly doing something. */
@keyframes proxy-status-breathe {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.45;
  }
}

/* The blanket stop in base.css stills this dot too, leaving a starting proxy to
   be told apart from a stuck one by reading the text next to it. What is kept
   here is not information — "Starting" is already spelled out beside the ring —
   but the difference between a dot that is working and one that has given up,
   which is the same reason the button's spinner keeps turning. Only the name
   changes; `!important` is what answers the `!important` on the universal rule,
   and the scoped selector is what outranks it. */
@media (prefers-reduced-motion: reduce) {
  .proxy-status__ring.starting .proxy-status__dot {
    animation-name: proxy-status-breathe !important;
    animation-duration: 1.5s !important;
    animation-iteration-count: infinite !important;
  }
}

.proxy-status__text {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
  /* Without this a long zh-CN label squeezes the button instead of wrapping (§5.5). */
  min-width: 0;
}

.proxy-status__title {
  font-size: var(--font-size-18);
  font-weight: var(--font-weight-bold);
  color: var(--text-primary);
}

.proxy-status__subtitle {
  font-size: var(--font-size-13);
  color: var(--text-secondary);
}

.proxy-status__actions {
  margin-left: auto;
  display: flex;
  gap: var(--space-2);
  flex-shrink: 0;
}

.proxy-status__pills {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-3);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-full);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-medium);
}

.pill--mode {
  background: var(--accent-subtle);
  color: var(--accent-text);
}

.pill--direct {
  background: var(--success-subtle);
  color: var(--success-text);
}

.pill--relay {
  background: var(--warning-subtle);
  color: var(--warning-text);
}

.pill--mixed {
  background: var(--bg-inset);
  color: var(--text-secondary);
}

/* Pushed to the trailing edge of the traffic row: it is the only figure there that is a count,
   and it reads as a summary of the two beside it rather than as a third of the same kind. */
.pill--flows {
  margin-left: auto;
}

.proxy-status__traffic {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2) var(--space-4);
  padding: var(--space-3);
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

/* The same two colours the node list on the Connect page uses for the same two directions, so
   "sent" is the same colour everywhere it appears. */
.traffic-figure {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  min-width: 0;
  font-size: var(--font-size-12);
}

.traffic-figure--sent {
  color: var(--warning-text);
}

.traffic-figure--received {
  color: var(--accent-text);
}

/* Monospace and tabular so successive polls do not shift the row as digits change width. */
.traffic-figure__value {
  font-family: var(--font-mono);
  font-size: var(--font-size-13);
  font-weight: 600;
  color: var(--text-primary);
}

.traffic-figure__rate {
  font-family: var(--font-mono);
  color: var(--text-muted);
}

.proxy-status__node {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3);
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

.proxy-status__label {
  font-size: var(--font-size-12);
  color: var(--text-secondary);
  flex-shrink: 0;
}

.proxy-status__value {
  flex: 1;
  min-width: 0;
  font-family: var(--font-mono);
  font-size: var(--font-size-12);
  line-height: var(--line-height-mono);
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

.proxy-status__copy {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-secondary);
  cursor: pointer;
  flex-shrink: 0;
}

.proxy-status__copy:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.proxy-status__copy:focus-visible {
  box-shadow: var(--focus-ring);
}

.proxy-status__tun {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

.proxy-status__tun-text {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
  flex: 1;
  min-width: 0;
}

.proxy-status__tun-label {
  font-size: var(--font-size-14);
  font-weight: var(--font-weight-medium);
  color: var(--text-primary);
}

.proxy-status__tun-hint {
  font-size: var(--font-size-12);
  color: var(--text-muted);
}

.proxy-status__error {
  margin: 0;
  padding: var(--space-3);
  border-left: 3px solid var(--error);
  border-radius: var(--radius-sm);
  background: var(--error-subtle);
  color: var(--error-text);
  font-size: var(--font-size-13);
}

.proxy-status__stale {
  margin: 0;
  font-size: var(--font-size-12);
  color: var(--warning-text);
}

@media (max-width: 600px) {
  .proxy-status__main {
    flex-wrap: wrap;
  }

  .proxy-status__actions {
    margin-left: 0;
    width: 100%;
  }
}
</style>

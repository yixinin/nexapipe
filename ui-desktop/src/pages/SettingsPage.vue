<script setup lang="ts">
import { computed, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import ServiceManager from "../components/ServiceManager.vue";
import { useI18n } from "vue-i18n";
import AppToggle from "../components/base/AppToggle.vue";
import { useConfigStore } from "../stores/config";
import { useProxyStore } from "../stores/proxy";
import { usePrefsStore } from "../stores/prefs";
import { useTheme } from "../composables/useTheme";
import { useLocale } from "../composables/useLocale";
import { useToast } from "../composables/useToast";
import { errorKey } from "../api/errors";
import type { ThemePreference } from "../stores/prefs";

const { t } = useI18n();
const { config, credentialProtection, updateConfig } = useConfigStore();
const toast = useToast();

/**
 * Where the credential master key ended up, in the user's words.
 *
 * Both answers mean the credentials are encrypted — what differs is who holds the key — so this
 * is information rather than a warning. `null` is not one of them: it means startup could not
 * ask, and claiming the keychain case it cannot confirm would be worse than saying so.
 */
const credentialProtectionLabel = computed(() => {
  switch (credentialProtection.value) {
    case 'keychain':
      return t('settings.credentialProtectionKeychain');
    case 'file':
      return t('settings.credentialProtectionFile');
    default:
      return t('settings.credentialProtectionUnknown');
  }
});
// Toggling the backend changes where the status comes from, so the panel has to re-read it.
const { refreshServiceRunning } = useProxyStore();

/**
 * Appearance is the one group that is not proxy configuration: theme and language are stored as
 * UI preferences, and both apply live — no reload, and no re-entering the page.
 */
const { preference: themePreference, setTheme } = useTheme();
const { locale, options: localeOptions, setLocale } = useLocale();

/** Labels are i18n keys: the language list is the control that has to stay readable in any UI
 *  language, so both selects resolve their text where they render. */
const themeOptions: { value: ThemePreference; label: string }[] = [
  { value: 'system', label: 'appearance.themeSystem' },
  { value: 'light', label: 'appearance.themeLight' },
  { value: 'dark', label: 'appearance.themeDark' },
];

function onThemeChange(event: Event): void {
  setTheme((event.target as HTMLSelectElement).value as ThemePreference);
}

function onLocaleChange(event: Event): void {
  setLocale((event.target as HTMLSelectElement).value);
}

/**
 * Whether the proxy runs inside the app or through the installed system service.
 *
 * It used to be presented as a "Proxy Mode" (Normal / Service), which is not what it selects:
 * the forwarding mode is TUN vs local proxy, and that is the switch on the Connect page. This is
 * only *where* the proxy runs, so it belongs with the service it depends on.
 */
const useServiceModel = computed({
  get: () => config.useService,
  set: (enabled: boolean) => {
    updateConfig({ useService: enabled });
    void refreshServiceRunning();
  },
});

/**
 * Whether the app is set to start when the machine does.
 *
 * `null` means "not known": the read failed, and a failed read is not "off" —
 * the entry may well be there. The switch says so by staying disabled rather
 * than by claiming a state nobody read.
 */
const autoStart = ref<boolean | null>(null);
const logLevel = ref("info");
const isLoading = ref(false);

/**
 * Whether the app is set to start when the machine does.
 *
 * The switch used to call two commands that were never registered, so it read
 * `false` and wrote nothing: a setting that looked like one and behaved like a
 * decoration.
 */
async function loadSettings() {
  isLoading.value = true;
  try {
    autoStart.value = await invoke<boolean>("is_auto_start_enabled");
  } catch (e) {
    // A read that fails is not "off": the entry may well be there. The switch
    // is left showing what is known — which is nothing, and which it says by
    // staying disabled — and the failure is reported rather than swallowed. A
    // silent `false` is the lie this used to tell: it claimed the entry was
    // gone, and clicking the switch then wrote it back.
    console.error("Failed to read the start-at-login setting:", e);
    // The backend says which failure it was, and its own code names the one
    // the user can act on ("the path of the running app could not be
    // resolved"); the generic one is only the fallback for a failure that
    // carries no code.
    toast.fromKey(errorKey(e, "error.autostart.read_failed"));
  }
  isLoading.value = false;
}

async function saveAutoStart() {
  const wanted = autoStart.value;
  if (wanted === null) {
    // Nothing was read, so there is no state to change.
    return;
  }
  try {
    await invoke("set_auto_start", { enabled: wanted });
  } catch (e) {
    console.error("Failed to set auto start:", e);
    // Put the switch back where it was: the setting did not change, so the
    // switch must not pretend it did.
    autoStart.value = !wanted;
    toast.fromKey(errorKey(e, "error.autostart.write_failed"));
  }
}

/**
 * Flips the start-at-login switch and writes the new state.
 *
 * A separate method rather than an inline expression, because the state has
 * three values and the inline one could only assume two.
 */
function toggleAutoStart(): void {
  if (autoStart.value === null) {
    return;
  }
  autoStart.value = !autoStart.value;
  void saveAutoStart();
}

/**
 * Whether closing the window hides it to the tray instead of ending the app.
 *
 * A preference rather than a proxy setting, so it lives with the theme and the
 * language.
 */
const { prefs, setMinimizeOnClose, setSilentStart, setAutoConnect } = usePrefsStore();

const minimizeOnClose = computed({
  get: () => prefs.minimizeOnClose,
  set: (value: boolean) => setMinimizeOnClose(value),
});

/**
 * Whether a launch the machine asked for shows a window.
 *
 * A preference rather than a proxy setting, so it lives with the theme and the
 * language: it is a statement about how the app should appear, not about how it
 * was started.
 */
const silentStart = computed({
  get: () => prefs.silentStart,
  set: (value: boolean) => setSilentStart(value),
});

/**
 * Whether the tunnel comes up by itself after a restart.
 *
 * Off until the user says otherwise: a proxy that reconnects on its own
 * forwards traffic on its own.
 */
const autoConnect = computed({
  get: () => prefs.autoConnect,
  set: (value: boolean) => setAutoConnect(value),
});

/**
 * Whether there is a tray to hide the window into.
 *
 * Without one, a hidden window is an app nobody can reach, so the switch is
 * offered only where it can be honoured. `null` is "not known yet": the
 * answer is a question for the app, and until it comes back the switch says
 * nothing about a tray that may not be there — and cannot be turned on for a
 * tray that does not exist.
 */
const trayAvailable = ref<boolean | null>(null);

async function loadTrayAvailability() {
  try {
    trayAvailable.value = await invoke<boolean>("is_tray_available");
  } catch {
    trayAvailable.value = false;
  }
}

/**
 * The version the running bundle was actually stamped with, read from the app instead of being
 * typed in here. A hardcoded string is a version bump that has to be remembered every release —
 * and the one thing that silently disagrees with tauri.conf.json when it is forgotten.
 */
const appVersion = ref("");

async function loadAppVersion() {
  try {
    appVersion.value = await getVersion();
  } catch {
    // Outside a Tauri window (a plain `vite dev`, say) there is nothing to read.
    appVersion.value = "";
  }
}

loadSettings();
loadTrayAvailability();
loadAppVersion();
</script>

<template>
  <div class="settings-page">
    <div class="settings-section">
      <div class="card-header">
        <h2>{{ t('appearance.title') }}</h2>
        <div class="card-header-decoration"></div>
      </div>

      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="5"/>
              <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('appearance.theme') }}</span>
              <span class="setting-hint">{{ t('appearance.themeHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <select class="select-input" :value="themePreference" @change="onThemeChange">
              <option v-for="option in themeOptions" :key="option.value" :value="option.value">
                {{ t(option.label) }}
              </option>
            </select>
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="2" y1="12" x2="22" y2="12"/>
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('appearance.language') }}</span>
              <span class="setting-hint">{{ t('appearance.languageHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <!-- Options carry their native name, so the control stays findable even when the
                 rest of the UI is in a language the reader does not understand. -->
            <select class="select-input" :value="locale" @change="onLocaleChange">
              <option v-for="option in localeOptions" :key="option.value" :value="option.value">
                {{ option.label }}
              </option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>{{ t('service.title') }}</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="backend-row">
        <div class="backend-text">
          <span class="backend-label">{{ t('service.routeThrough') }}</span>
          <span class="backend-hint">{{ t('service.routeThroughHint') }}</span>
        </div>
        <AppToggle v-model="useServiceModel" :label="t('service.routeThrough')" />
      </div>

      <ServiceManager />
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>{{ t('settings.security') }}</h2>
        <div class="card-header-decoration"></div>
      </div>

      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.credentialProtection') }}</span>
              <span class="setting-hint">{{ t('settings.credentialProtectionHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <span class="protection-level">{{ credentialProtectionLabel }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>{{ t('settings.tun') }}</h2>
        <div class="card-header-decoration"></div>
      </div>

      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
              <line x1="12" y1="22" x2="12" y2="15.5"/>
              <line x1="22" y1="8.5" x2="12" y2="15.5"/>
              <line x1="2" y1="8.5" x2="12" y2="15.5"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.tunDeviceName') }}</span>
              <span class="setting-hint">{{ t('settings.tunDeviceNameHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <input
              v-model="config.tunName"
              class="text-input"
              placeholder="nexa-tun"
              maxlength="15"
              @change="updateConfig({ tunName: config.tunName.trim() || 'nexa-tun' })"
            />
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>{{ t('settings.app') }}</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 8v4l3 3"/>
              <circle cx="12" cy="12" r="10"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.launchAtStartup') }}</span>
              <span class="setting-hint">{{ t('settings.launchAtStartupHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <button
              class="toggle"
              :class="{ active: autoStart === true }"
              :disabled="autoStart === null"
              @click="toggleAutoStart()"
            >
              <div class="toggle-thumb"></div>
            </button>
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M4 12a8 8 0 0 1 16 0"/>
              <path d="M12 12l4-4"/>
              <circle cx="12" cy="12" r="2"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.autoConnect') }}</span>
              <span class="setting-hint">{{ t('settings.autoConnectHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <AppToggle v-model="autoConnect" :label="t('settings.autoConnect')" />
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.silentStart') }}</span>
              <span class="setting-hint">{{ t('settings.silentStartHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <AppToggle v-model="silentStart" :label="t('settings.silentStart')" />
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M5 12h14M12 5l7 7-7 7"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.minimizeOnClose') }}</span>
              <span class="setting-hint">{{ trayAvailable === false ? t('settings.minimizeOnCloseUnavailable') : t('settings.minimizeOnCloseHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <button
              class="toggle"
              :class="{ active: minimizeOnClose }"
              :disabled="trayAvailable !== true"
              @click="minimizeOnClose = !minimizeOnClose"
            >
              <div class="toggle-thumb"></div>
            </button>
          </div>
        </div>
        
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
              <line x1="16" y1="13" x2="8" y2="13"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">{{ t('settings.logLevel') }}</span>
              <span class="setting-hint">{{ t('settings.logLevelHint') }}</span>
            </div>
          </div>
          <div class="setting-right">
            <select v-model="logLevel" class="select-input">
              <option value="trace">{{ t('logs.levelTrace') }}</option>
              <option value="debug">{{ t('logs.levelDebug') }}</option>
              <option value="info">{{ t('logs.levelInfo') }}</option>
              <option value="warn">{{ t('logs.levelWarn') }}</option>
              <option value="error">{{ t('logs.levelError') }}</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>{{ t('settings.about') }}</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="about-info">
        <div class="about-item">
          <span class="about-label">{{ t('common.version') }}</span>
          <span class="about-value">{{ appVersion ? "v" + appVersion : "—" }}</span>
        </div>
        <div class="about-item">
          <span class="about-label">{{ t('settings.builtWith') }}</span>
          <span class="about-value">Tauri + Vue 3</span>
        </div>
        <div class="about-item">
          <span class="about-label">{{ t('settings.license') }}</span>
          <span class="about-value">MIT License</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.settings-page::-webkit-scrollbar {
  width: 4px;
}

.settings-page::-webkit-scrollbar-track {
  background: transparent;
}

.settings-page::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 2px;
}

.settings-section {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 20px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}

.card-header h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-header-decoration {
  flex: 1;
  height: 2px;
  background: var(--gradient-primary);
  border-radius: 1px;
}

/* The execution backend, sitting with the service it depends on: this chooses *where* the proxy
   runs, not what it does — that is the TUN switch on the Connect page. */
.backend-row {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-bottom: 16px;
  padding: 12px 14px;
  background: var(--surface-2);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-md);
}

.backend-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
  min-width: 0;
}

.backend-label {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
}

.backend-hint {
  font-size: 11px;
  color: var(--text-muted);
}

.mode-options {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.mode-option {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px;
  background: var(--surface-2);
  border-radius: var(--radius-md);
  border: 2px solid transparent;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.mode-option:hover {
  background: var(--surface-3);
  border-color: var(--primary-200);
}

.mode-option.active {
  background: var(--primary-50);
  border-color: var(--primary-400);
}

.mode-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.mode-icon svg {
  width: 20px;
  height: 20px;
}

.mode-icon.normal {
  background: var(--success-100);
  color: var(--success-600);
}

.mode-icon.service {
  background: var(--warning-100);
  color: var(--warning-600);
}

.mode-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.mode-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.mode-desc {
  font-size: 12px;
  color: var(--text-muted);
}

.mode-radio {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  border: 2px solid var(--border-color);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all var(--transition-normal);
}

.mode-option.active .mode-radio {
  border-color: var(--primary-500);
}

.radio-inner {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: transparent;
  transition: all var(--transition-normal);
}

.mode-option.active .radio-inner {
  background: var(--primary-500);
}

.settings-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 0;
  border-bottom: 1px solid var(--border-light);
}

.setting-item:last-child {
  border-bottom: none;
}

.setting-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.setting-left svg {
  width: 18px;
  height: 18px;
  color: var(--text-muted);
}

.setting-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.setting-label {
  font-size: 14px;
  font-weight: 500;
  color: var(--text-primary);
}

.setting-hint {
  font-size: 12px;
  color: var(--text-muted);
}

.setting-right {
  flex-shrink: 0;
}

/* A read-only answer, not a control: it says where the credential key is, and there is
   nothing here to change. */
.protection-level {
  font-size: 13px;
  color: var(--text-secondary);
  text-align: right;
}

.toggle {
  width: 44px;
  height: 24px;
  background: var(--surface-4);
  border-radius: 12px;
  border: none;
  cursor: pointer;
  position: relative;
  transition: background var(--transition-normal);
}

.toggle.active {
  background: var(--primary-500);
}

/* A switch that cannot be honoured says so by looking like it: dimmed, and
   refusing the pointer rather than accepting a click it would throw away. */
.toggle:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.toggle-thumb {
  position: absolute;
  top: 3px;
  left: 3px;
  width: 18px;
  height: 18px;
  background: white;
  border-radius: 50%;
  transition: transform var(--transition-normal);
  box-shadow: var(--shadow-sm);
}

.toggle.active .toggle-thumb {
  transform: translateX(20px);
}

.select-input {
  padding: 8px 12px;
  border: 1.5px solid var(--border-color);
  border-radius: var(--radius-sm);
  font-size: 13px;
  background: var(--surface-1);
  color: var(--text-primary);
  cursor: pointer;
  transition: all var(--transition-normal);
}

.select-input:focus {
  outline: none;
  border-color: var(--primary-500);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.text-input {
  width: 160px;
  padding: 8px 12px;
  border: 1.5px solid var(--border-color);
  border-radius: var(--radius-sm);
  font-size: 13px;
  background: var(--surface-1);
  color: var(--text-primary);
  transition: all var(--transition-normal);
}

.text-input:focus {
  outline: none;
  border-color: var(--primary-500);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.about-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.about-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.about-label {
  font-size: 13px;
  color: var(--text-muted);
}

.about-value {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
}

@media (max-width: 600px) {
  .mode-option {
    flex-direction: column;
    align-items: flex-start;
  }
  
  .mode-radio {
    margin-left: auto;
  }
}
</style>

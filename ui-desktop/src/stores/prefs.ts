/**
 * UI preferences: theme, language, sidebar state (docs/ui-refactor-plan.md §5.7).
 *
 * Separate from the user's proxy configuration on purpose — losing a theme choice is a shrug,
 * losing node configuration is not, and the two have different migration stories.
 */
import { reactive, watch } from 'vue';

export type ThemePreference = 'system' | 'light' | 'dark';

export interface Prefs {
  theme: ThemePreference;
  /** Resolved locale tag, e.g. `en` or `zh-CN`. */
  locale: string;
  sidebarCollapsed: boolean;
  /**
   * Whether closing the window hides it to the tray instead of ending the app.
   *
   * True by default: the app has a tray icon, so the window is one of two ways
   * into it rather than the only one, and a proxy that stops when the window
   * closes is not the always-on proxy the setting promises.
   */
  minimizeOnClose: boolean;
  /**
   * Whether a launch the machine asked for shows a window.
   *
   * True by default: a window appearing over whatever the user was doing at
   * login is exactly what a launch nobody asked for should not do. Turning it
   * off says the opposite — this particular user wants to see the app come up.
   *
   * Only about launches the *machine* asked for. A launch the user made shows
   * its window whatever this says, because the user is already looking at it.
   */
  silentStart: boolean;
  /**
   * Whether the tunnel is brought up by itself after a restart.
   *
   * False by default: a proxy that reconnects on its own forwards traffic on
   * its own, and that is the user's decision to make rather than the app's.
   *
   * The same shape as the Android app's "connect after a restart", and for the
   * same reason: the switch says the machine should come up protected, and it
   * is off until someone asks for it.
   */
  autoConnect: boolean;
}

const STORAGE_KEY = 'nexapipe.prefs';

const defaultPrefs: Prefs = {
  theme: 'system',
  locale: '',
  sidebarCollapsed: false,
  minimizeOnClose: true,
  silentStart: true,
  autoConnect: false,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...defaultPrefs };
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return { ...defaultPrefs };

    const theme: ThemePreference =
      parsed.theme === 'light' || parsed.theme === 'dark' || parsed.theme === 'system'
        ? parsed.theme
        : defaultPrefs.theme;

    return {
      theme,
      locale: typeof parsed.locale === 'string' ? parsed.locale : defaultPrefs.locale,
      sidebarCollapsed:
        typeof parsed.sidebarCollapsed === 'boolean'
          ? parsed.sidebarCollapsed
          : defaultPrefs.sidebarCollapsed,
      minimizeOnClose:
        typeof parsed.minimizeOnClose === 'boolean'
          ? parsed.minimizeOnClose
          : defaultPrefs.minimizeOnClose,
      silentStart:
        typeof parsed.silentStart === 'boolean' ? parsed.silentStart : defaultPrefs.silentStart,
      autoConnect:
        typeof parsed.autoConnect === 'boolean' ? parsed.autoConnect : defaultPrefs.autoConnect,
    };
  } catch (error) {
    console.error('[prefs] failed to load:', error);
    return { ...defaultPrefs };
  }
}

const prefs = reactive<Prefs>(loadPrefs());

watch(
  () => ({ ...prefs }),
  (next) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch (error) {
      console.error('[prefs] failed to save:', error);
    }
  },
  { deep: true },
);

export function usePrefsStore() {
  function setTheme(theme: ThemePreference): void {
    prefs.theme = theme;
  }

  function setLocale(locale: string): void {
    prefs.locale = locale;
  }

  function setSidebarCollapsed(collapsed: boolean): void {
    prefs.sidebarCollapsed = collapsed;
  }

  function setMinimizeOnClose(minimize: boolean): void {
    prefs.minimizeOnClose = minimize;
  }

  function setSilentStart(silent: boolean): void {
    prefs.silentStart = silent;
  }

  function setAutoConnect(auto: boolean): void {
    prefs.autoConnect = auto;
  }

  function toggleSidebar(): void {
    prefs.sidebarCollapsed = !prefs.sidebarCollapsed;
  }

  return {
    prefs,
    setTheme,
    setLocale,
    setSidebarCollapsed,
    setMinimizeOnClose,
    setSilentStart,
    setAutoConnect,
    toggleSidebar,
  };
}

/**
 * Synchronous read used before the app mounts, so the first paint already has the right theme
 * and no flash of the wrong one occurs (§5.4).
 */
export function readStoredTheme(): ThemePreference {
  return prefs.theme;
}

export function readStoredLocale(): string {
  return prefs.locale;
}

/**
 * Application entry (§3.2, §5.4, §5.11 rule 1).
 *
 * Order is the whole point of this file:
 *
 *   1. styles, in dependency order — raw tokens, then the semantic theme mapping, then the reset
 *   2. the theme attribute, *before* mount, so the first paint is already the right theme and no
 *      white flash happens on a dark-mode machine (§5.4)
 *   3. the platform flag, also before mount: the shell decides whether to draw its own window
 *      controls from it, and resolving it after mount would show Linux users a set of buttons that
 *      then disappear
 *   4. `<html lang>` and the document title from the resolved locale (D14)
 *   5. mount
 *   6. show the window, which the backend created hidden
 *
 * Runtime proxy state is deliberately last and not awaited: it needs the backend, and the shell
 * renders `stopped` until the first status arrives.
 */
import { createApp, watch } from 'vue';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { invoke } from '@tauri-apps/api/core';
import App from './App.vue';
import router from './router';
import i18n, { currentLocale, resolveLocale, setI18nLocale } from './i18n';
import { applyStoredTheme } from './composables/useTheme';
import { initPlatform } from './composables/useWindowControls';
import { readStoredLocale, usePrefsStore } from './stores/prefs';
import { isBackgroundLaunch } from './api/autostart';
import { setTrayLabels } from './api/tray';
import { initProxyState, onAppFocused, refreshTrayStatus } from './stores/proxy';
import { initGate, refreshGate } from './stores/gate';
import { initConfigStore, initConfigStoreDeferred } from './stores/config';
import { flushStartupTiming, mark } from './app/startup';

import './styles/tokens.css';
import './styles/themes.css';
import './styles/base.css';
// Temporary: the token names the not-yet-migrated pages still use. Removed with them (§7).
import './styles/legacy.css';

// Every static import above has been evaluated by now, so this is where the bundle's own cost
// ends. Measured from the document navigation: see `app/startup.ts`.
mark('module-start');

applyStoredTheme();

/**
 * Shows the window the backend created hidden.
 *
 * Everything above this line runs before anything is on screen, so a slow start — a cold
 * WebView2, an awaited credential read — used to leave the user looking at an empty frame with
 * the app's own background filling it. Waiting until the app has mounted and painted means the
 * window appears already drawn instead.
 *
 * The window is shown *before* a frame is waited for, not after.
 *
 * It used to be the other way round, and that never worked: the window is hidden until this
 * call, and a hidden window is not composited, so `requestAnimationFrame` is not scheduled for
 * it. Waiting for a frame before showing waited for the one thing it was there to enable — and
 * resolved only ten seconds later, when the backend's fallback showed the window anyway. Until
 * then the application was indistinguishable from one that had not started.
 *
 * Showing straight after `mount()` is safe for a different reason: `mount()` is synchronous, so
 * the tree is already in the document, and the window carries the app's own background colour
 * from `tauri.conf.json` — the frame the user sees first is never a white one.
 *
 * A frame is still awaited, after the show rather than before it, so the log records how long
 * the first real paint took: that is the number the frontend's own timings are here to produce,
 * and `show()` cannot report it. The wait is bounded, because a frame is not something this side
 * can count on being scheduled — see `firstFrame` — and one that never arrives must not be the
 * reason the timings are never sent.
 *
 * Failure is not fatal and neither is a plain browser: `vite dev` has no Tauri window and the
 * call rejects, which is expected and says nothing about the app.
 *
 * `shown` is the moment the user has been waiting for, so it is also the moment the timings are
 * worth sending: a measurement that added its own round-trip to the wait would be measuring
 * itself.
 */

/// How long the first frame is waited for before the wait is given up on.
///
/// Two seconds: a frame that is slow is not the same as a frame that never comes, and the first
/// is a machine having a bad day while the second is a webview that is not being composited.
const FIRST_FRAME_WAIT_MS = 2000;

/**
 * Resolves `true` on the next animation frame, or `false` when `limit` passes without one.
 *
 * A hidden page is not fed frames, and neither is a webview the compositor has stopped drawing —
 * a minimized window, or one on a machine that has just gone to sleep. Those are exactly the
 * launches a timing is worth having from, so an unbounded wait would be worse than a slow one:
 * the `finally` below it would never run, and that launch would send no report at all.
 */
function firstFrame(limit: number): Promise<boolean> {
  return new Promise((resolve) => {
    let frame = 0;
    const timer = setTimeout(() => {
      cancelAnimationFrame(frame);
      resolve(false);
    }, limit);
    frame = requestAnimationFrame(() => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

async function showWindow(): Promise<void> {
  try {
    // A launch the machine asked for comes up in the tray instead: a window
    // appearing over whatever the user was doing at login is exactly what a
    // launch nobody asked for should not do. The backend's own fallback knows the
    // same thing and does not show it either.
    //
    // Unless the user asked otherwise. `silentStart` is that preference: it says
    // whether a machine-started launch is a quiet one, and a user who wants to
    // see the app come up at login turns it off. The flag says *who* started the
    // app; this says whether that launch should be quiet.
    //
    // Unless there is no tray to come up in. The tray is built on a best-effort
    // basis and can fail — a bare session, a container, a Linux host without a
    // StatusNotifier — and an app with no window and no tray icon is an app
    // nobody can reach again.
    if ((await isBackgroundLaunch()) && silentStart() && (await isTrayAvailable())) {
      mark('background');
      return;
    }
    await getCurrentWindow().show();
    mark('shown');
    // Marked only when a frame really arrived: a start-up that produced none is one the log
    // should say so about, not one to fill in with the moment the wait gave up.
    if (await firstFrame(FIRST_FRAME_WAIT_MS)) {
      mark('first-frame');
    }
  } catch (error) {
    console.warn('[window] could not show the window:', error);
  } finally {
    void flushStartupTiming();
  }
}

/**
 * Whether a launch the machine asked for should be a quiet one.
 *
 * Read from the preferences rather than asked of the backend, because the
 * preference is the user's and lives beside the theme and the language: it is
 * a statement about how the app should appear, not about how it was started.
 */
function silentStart(): boolean {
  return usePrefsStore().prefs.silentStart;
}

/**
 * Whether the tray icon exists.
 *
 * A failure is a "no": a tray that cannot be reached cannot be come back to,
 * and the window has to be shown instead.
 */
async function isTrayAvailable(): Promise<boolean> {
  try {
    return await invoke<boolean>('is_tray_available');
  } catch {
    return false;
  }
}

async function bootstrap(): Promise<void> {
  await initPlatform();
  mark('platform-done');

  // Credentials are read from the encrypted store, which is asynchronous, so this is awaited
  // before mount: a page must never render a node's 2FA as absent and then fill it in.
  await initConfigStore();
  mark('credentials-done');

  // The composition root owns the *initial* locale; `useLocale` owns every later change, so the
  // two cannot fight over the value — both resolve it the same way.
  setI18nLocale(resolveLocale(readStoredLocale()));

  const app = createApp(App);
  app.use(i18n);
  app.use(router);
  app.mount('#app');
  mark('mounted');

  // The window exists from the start but is not shown until there is something in it.
  void showWindow();

  // The tray menu is written in the user's language, which is only known now.
  void setTrayLabels();

  // The tray menu is a native menu and not a template, so a language change does
  // not reach it on its own: the labels have to be written again, or the tray
  // keeps the language the app started in while everything else has changed.
  // The status on the icon is in the same language, so it is written again too.
  watch(
    () => currentLocale(),
    () => {
      void setTrayLabels();
      refreshTrayStatus();
    },
  );

  // Everything from here on is a projection no first screen renders, so it must not sit between
  // the mount and the paint: the display masks cost two IPC round-trips per configured node.
  void initConfigStoreDeferred();

  // The door is read before the first paint too, so a page cannot draw an open
  // lock and then shut it.
  void initGate();

  void initProxyState();

  // The status poll keeps running in the background, but a machine that was just asleep has been
  // showing the status it had before it slept — read immediately instead of waiting the interval.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return;
    onAppFocused();
    // The one moment worth asking the machine again whether it can still confirm
    // anybody: a password removed or a fingerprint deleted while the app was in
    // the background must not leave a window open nobody can answer for.
    void refreshGate();
  });
}

void bootstrap();

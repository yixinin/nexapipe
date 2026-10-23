/**
 * The tray icon's half of the app: the menu's words and the state on the icon.
 *
 * Both are the renderer's to say. The tray lives in the backend and the
 * translations live here, so the words are handed over rather than looked up
 * there — the same arrangement the credential gate uses for its prompt.
 */
import { invoke } from '@tauri-apps/api/core';
import { translate } from '../i18n';

/**
 * Writes the menu's labels.
 *
 * The words are translated here rather than handed in, because the locale is
 * the one thing that decides them and the caller does not know it.
 *
 * Best effort: a tray whose menu is in the wrong language is still a working
 * tray, and the backend keeps English until it hears otherwise.
 */
export async function setTrayLabels(): Promise<void> {
  try {
    await invoke('set_tray_labels', {
      showLabel: translate('tray.show'),
      quitLabel: translate('tray.quit'),
    });
  } catch (error) {
    console.debug('[tray] the menu labels could not be set:', error);
  }
}

/**
 * Writes the connection state onto the tray icon.
 *
 * A word rather than a colour: the icon is the app's only always-on surface,
 * and a coloured dot would ask the user to learn what the colour means.
 */
export async function setTrayStatus(status: string): Promise<void> {
  await invoke('set_tray_status', { status });
}

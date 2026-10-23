/**
 * The start-at-login half of the app: whether the machine started it.
 *
 * The flag says *who* started the app, not whether a window should appear.
 * That is a separate statement — the user's preference — and keeping the two
 * apart is what lets a user who wants the window at login have it without the
 * entry being rewritten.
 */
import { invoke } from '@tauri-apps/api/core';

/**
 * Whether the machine started this app rather than the user.
 *
 * True when the start-at-login entry launched it. A launch the user made is
 * not one: they are already looking at it, and it shows its window.
 */
export async function isBackgroundLaunch(): Promise<boolean> {
  try {
    return await invoke<boolean>('is_background_launch');
  } catch {
    // A failure is a "no": a launch that cannot tell is a launch that shows its
    // window, which is the ordinary case. Both callers need that answer, so it
    // is decided here rather than in each of them — and a launch the backend
    // cannot answer for must neither take the window down with it nor let an
    // automatic connection start on a guess.
    return false;
  }
}

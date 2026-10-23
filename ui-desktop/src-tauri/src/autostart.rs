//! Whether this app starts when the machine does.
//!
//! The settings page has carried a "launch at startup" switch for as long as it
//! has had a settings page, and it called two commands that were never
//! registered: the switch read `false` and wrote nothing, so it looked like a
//! setting and behaved like a decoration.
//!
//! Each platform says this differently, and none of them is hard:
//!
//! - **Windows**: a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//! - **macOS**: a LaunchAgent in `~/Library/LaunchAgents`.
//! - **Linux**: a `.desktop` file under `~/.config/autostart`.
//!
//! All three are per-user: starting an app at login is the user's own
//! business, and none of them needs elevation.
//!
//! # Nothing is started now
//!
//! Enabling this writes an entry and stops there. The entry is read at the next
//! login by the platform's own mechanism — the Run key, `launchd`, the
//! session's autostart scan — so switching the setting on does not launch a
//! second copy of the app in the middle of the session, which is what a
//! `launchctl bootstrap` here would do.
//!
//! The entry carries [`BACKGROUND_FLAG`], so the app that comes up at login knows the
//! machine started it rather than the user. What that launch does with its window is
//! the user's preference and lives with the theme and the language; the flag says
//! *who* started the app, and the two are separate so that a user who wants the
//! window at login can have it without the entry being rewritten.

use std::path::PathBuf;

use crate::error::{codes, AppError};

/// The name the entry is filed under.
///
/// One word on every platform, because it is what the user reads in whatever
/// list the platform keeps — "Startup" on Windows, "Login Items" on macOS, the
/// session's autostart list on Linux.
///
/// macOS files its agent under the bundle identifier instead, which is what
/// the system's own login items are named after, so this one is unused there.
#[cfg_attr(target_os = "macos", allow(dead_code))]
const ENTRY_NAME: &str = "nexa";

/// The argument that says "the machine started this app".
///
/// Carried by the entry, so the app that comes up at login knows it was the
/// machine's doing rather than the user's, and can decide what that means:
/// whether a window appears is the user's preference (`autoConnect` and
/// `silentStart` in the frontend), not something the entry decides.
///
/// The name is historical. It used to mean "start without a window", and it
/// still does by default — but the meaning moved to the preference, so that a
/// user who wants the window at login can have it without rewriting the entry.
pub const BACKGROUND_FLAG: &str = "--background";

/// Whether this app is started when the machine starts.
///
/// A failure to read is a failure, not "off": a switch that claims to be off
/// while the entry is there is the same silent lie the switch used to tell.
pub fn is_enabled() -> Result<bool, AppError> {
    platform::is_enabled()
}

/// What the answers of `reg query` mean about the start-at-login entry.
///
/// `reg query` exits 1 both when the value is not there and when the key
/// cannot be read, and the text that says which is localized, so it is not
/// read. The key and the key above it are asked as well, and what they
/// answered is what tells the two apart.
///
/// The answers are, in order: the value, the key, and the key's parent.
///
/// Not a Windows-only rule — it is about what `reg query` answers, and the
/// rule is the same wherever it is asked — but only Windows asks it, so the
/// dead-code lint is silenced elsewhere.
#[cfg_attr(not(windows), allow(dead_code))]
fn registry_answers(value: bool, key: bool, parent: bool) -> Result<bool, AppError> {
    if value {
        return Ok(true);
    }
    // The key can be read and holds no such value: the entry is not there.
    if key {
        return Ok(false);
    }
    // The key is not there either: there is nowhere for the entry to be.
    if parent {
        return Ok(false);
    }
    // Nothing could be read. A failure to read is not "off": a switch that
    // claims to be off while the entry is there is the same silent lie the
    // switch used to tell.
    Err(AppError::with_detail(
        codes::AUTOSTART_READ_FAILED,
        "the registry could not be read".to_string(),
    ))
}

/// Arranges for this app to start when the machine starts, or not.
///
/// Turning it off removes the entry. Turning it on writes one that points at
/// the running executable — which is the installed one for an installed app,
/// and a development build for a development build, so the second is what a
/// developer wants to happen.
pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
    platform::set_enabled(enabled)
}

/// Whether this launch was asked for by the machine rather than by a person.
///
/// True when the entry started the app. The app came up because the machine
/// said so, and what that means for the window is the user's preference rather
/// than this flag's: the flag says *who* started the app, and the frontend
/// decides whether that launch is a quiet one.
///
/// Kept separate from the window on purpose. A flag that said "no window" would
/// make "the machine started this app" and "the user does not want to be
/// interrupted" the same statement, and a user who wants the window at login
/// could not have it without rewriting the entry.
pub fn is_background_launch() -> bool {
    // `args_os` rather than `args`: the latter panics on a non-UTF-8 argument, and the launcher
    // that starts the app at login is not ours to control. A panic here would take the whole
    // start-up down — this runs inside the `setup` hook — over an argument nobody chose.
    std::env::args_os().any(|arg| arg == std::ffi::OsStr::new(BACKGROUND_FLAG))
}

/// The path of the running executable, which is what an entry has to point at.
fn current_exe() -> Result<PathBuf, AppError> {
    std::env::current_exe().map_err(|e| {
        AppError::with_detail(
            codes::AUTOSTART_EXE_PATH,
            format!("the running executable could not be resolved: {e}"),
        )
    })
}

/// The characters the specification reserves in a command line.
///
/// Space, tab, newline, `"`, `'`, `\`, `>`, `<`, `~`, `|`, `&`, `;`, `$`, `*`,
/// `?`, `#`, `(` and `)`, plus the backtick. A reserved character that is not
/// quoted ends the program name early — a path with an `&` in it, say, is read
/// as a path and a background job — so a path carrying one is quoted.
///
/// One string rather than a list of characters, because a list of them is laid
/// out by the formatter and the set belongs to the specification rather than
/// to this file.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RESERVED: &str = " \t\n\"'\\><~| &;$*?#()`";

/// The program's path, as the `Exec` line has to carry it.
///
/// That line is a command line, and the reserved characters above are the
/// ones that need quoting there.
///
/// Inside the quotes, four characters still need an escape of their own:
/// the quote, the backtick, the dollar sign and the backslash. The
/// backslash needs two of them: the escape rule for a string value is
/// applied before the quoting rule, so a literal backslash is four
/// backslashes in the file.
///
/// A `%` is a field code otherwise — the specification expands those
/// before the program ever sees the path — so a literal one is written
/// `%%`.
///
/// At the top level rather than in the Linux module, because it is a pure
/// function of the path and the rules of the specification: its tests are
/// then the same on every platform, and a platform that never writes a
/// `.desktop` file still gets them checked.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn quote_argument(exe: &std::path::Path) -> String {
    let exe = exe.display().to_string();
    if !exe.chars().any(|c| RESERVED.contains(c)) {
        // Quoting is only needed where it changes the meaning, but a field
        // code is expanded either way.
        return exe.replace('%', "%%");
    }
    let mut quoted = String::with_capacity(exe.len() + 2);
    quoted.push('"');
    for c in exe.chars() {
        match c {
            '"' | '`' | '$' => {
                quoted.push('\\');
                quoted.push(c);
            }
            // The escape rule runs before the quoting rule, so a literal
            // backslash is two escapes of its own.
            '\\' => quoted.push_str("\\\\\\\\"),
            '%' => quoted.push_str("%%"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

// -- Windows ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::{current_exe, ENTRY_NAME};
    use crate::error::{codes, AppError};
    use crate::win;

    /// Where Windows looks for what to run at login.
    ///
    /// The hive is part of the path: `reg` rejects a key without a root key with a
    /// syntax error, which the three-answer rule above would otherwise report as an
    /// unreadable registry.
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    /// The key above it, asked when the Run key cannot be read.
    const RUN_KEY_PARENT: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion";

    /// `reg.exe`, which is in `System32` on every Windows that has ever run.
    ///
    /// Named by path rather than by bare name: an app launched from a service
    /// or from a shell whose `PATH` does not include `System32` would
    /// otherwise fail to find it, and the failure would be "the setting does
    /// not work" rather than "the tool was not found".
    fn reg() -> String {
        std::env::var("SystemRoot")
            .map(|root| format!(r"{root}\System32\reg.exe"))
            .unwrap_or_else(|_| "reg.exe".to_string())
    }

    /// Runs `reg query` and reports whether it succeeded.
    ///
    /// The exit code is what is read; the text is localized, so it is not.
    fn query(args: &[&str]) -> Result<bool, AppError> {
        win::hidden(reg())
            .args(args)
            .output()
            .map(|output| output.status.success())
            .map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_READ_FAILED,
                    format!("reg query could not be run: {e}"),
                )
            })
    }

    pub fn is_enabled() -> Result<bool, AppError> {
        // Three questions, because `reg query` cannot tell "the value is not
        // there" from "the key cannot be read" on its own: the value itself,
        // the key it would be in, and the key above that one.
        super::registry_answers(
            query(&["query", RUN_KEY, "/v", ENTRY_NAME])?,
            query(&["query", RUN_KEY])?,
            query(&["query", RUN_KEY_PARENT])?,
        )
    }

    pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
        let mut command = win::hidden(reg());
        if enabled {
            let exe = current_exe()?;
            // The value is a command line, so the path is quoted: a program
            // files under `C:\Program Files` has a space in it.
            let value = format!("\"{}\" {}", exe.display(), super::BACKGROUND_FLAG);
            command.args([
                "add",
                RUN_KEY,
                "/v",
                ENTRY_NAME,
                "/t",
                "REG_SZ",
                "/d",
                value.as_str(),
                "/f",
            ]);
        } else {
            // Removing an entry that is not there is the outcome the caller
            // asked for, so it is not a failure — and `reg delete` exits
            // non-zero when the value is missing.
            if !is_enabled()? {
                return Ok(());
            }
            command.args(["delete", RUN_KEY, "/v", ENTRY_NAME, "/f"]);
        }

        let output = command.output().map_err(|e| {
            AppError::with_detail(
                codes::AUTOSTART_WRITE_FAILED,
                format!("reg could not be run: {e}"),
            )
        })?;

        if output.status.success() {
            Ok(())
        } else {
            Err(AppError::with_detail(
                codes::AUTOSTART_WRITE_FAILED,
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{RUN_KEY, RUN_KEY_PARENT};

        #[test]
        fn the_registry_keys_name_their_hive() {
            // A path with no root key is a syntax error to `reg`, not a missing entry.
            for key in [RUN_KEY, RUN_KEY_PARENT] {
                assert!(key.starts_with("HKCU\\"), "{key}");
            }
        }
    }
}

// -- macOS -----------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::current_exe;
    use crate::error::{codes, AppError};
    use std::path::PathBuf;

    /// The LaunchAgent's label.
    ///
    /// The bundle identifier, so the job is named after the app rather than
    /// after this file — the same name the system's own login items use.
    const LABEL: &str = "com.nexa.ui";

    /// Where the user agent goes.
    ///
    /// The code is the one the caller reports a failure under: not finding
    /// the agent and not being able to write it are different failures.
    fn plist_path(code: &str) -> Result<PathBuf, AppError> {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            AppError::with_detail(
                code,
                "HOME is not set, so there is no place to put a LaunchAgent",
            )
        })?;
        Ok(home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    pub fn is_enabled() -> Result<bool, AppError> {
        let path = plist_path(codes::AUTOSTART_READ_FAILED)?;
        // `metadata` rather than `exists`: the latter answers "no" for an
        // agent that cannot be read as well as for one that is not there,
        // and a read failure is not the same answer as "off".
        match std::fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(AppError::with_detail(
                codes::AUTOSTART_READ_FAILED,
                format!("the LaunchAgent could not be read: {e}"),
            )),
        }
    }

    pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
        let path = plist_path(codes::AUTOSTART_WRITE_FAILED)?;
        if !enabled {
            // Removing a file that is not there is the outcome the caller
            // asked for, so it is not a failure.
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the LaunchAgent could not be removed: {e}"),
                )),
            }
        } else {
            let exe = current_exe()?;
            let content = plist_content(&exe);
            let dir = path.parent().expect("the path has a parent");
            std::fs::create_dir_all(dir).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the LaunchAgents directory could not be created: {e}"),
                )
            })?;
            std::fs::write(&path, content).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the LaunchAgent could not be written: {e}"),
                )
            })?;
            // `launchd` refuses a world-writable agent, and the default mode
            // of a new file follows the umask — which on a machine with a
            // permissive umask would be 0666.
            set_private_mode(&path);
            Ok(())
        }
    }

    /// The agent itself.
    ///
    /// `RunAtLoad` is what makes the job start when the session comes up; the
    /// agent is not bootstrapped here, so nothing starts until the next
    /// login.
    fn plist_content(exe: &std::path::Path) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
            xml_escape(&exe.display().to_string()),
            super::BACKGROUND_FLAG,
        )
    }

    /// The path as XML text.
    ///
    /// The path is interpolated into a `<string>`, and XML gives `&`, `<` and
    /// `>` a meaning of their own. A path carrying one of them — `&` is the
    /// common one, in a directory name — makes the plist malformed, and
    /// `launchd` then refuses the agent: the entry is written, the switch says
    /// "on", and nothing starts at the next login.
    fn xml_escape(text: &str) -> String {
        let mut escaped = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                _ => escaped.push(c),
            }
        }
        escaped
    }

    /// Narrows the mode of a file to 0644, where the platform has one.
    #[cfg(unix)]
    fn set_private_mode(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }

    #[cfg(not(unix))]
    fn set_private_mode(_path: &std::path::Path) {}

    #[cfg(test)]
    mod tests {
        use super::plist_content;
        use std::path::Path;

        #[test]
        fn the_agent_carries_the_executable_and_the_background_flag() {
            // The two arguments are separate entries in the array, so a path
            // with a space in it needs no quoting here — and the flag has to be
            // one of them, or the app comes up with a window at login.
            let plist = plist_content(Path::new("/Applications/nexa.app/nexa"));
            assert!(plist.contains("<string>/Applications/nexa.app/nexa</string>"));
            assert!(plist.contains("<string>--background</string>"));
        }

        #[test]
        fn the_agent_starts_with_the_session() {
            // `RunAtLoad` is what makes the job run at login; without it the
            // entry would be a job that never starts.
            assert!(plist_content(Path::new("/Applications/nexa.app/nexa"))
                .contains("<key>RunAtLoad</key>"));
        }

        #[test]
        fn a_path_with_xml_in_it_is_escaped() {
            // An unescaped `&` makes the plist malformed, and `launchd` refuses
            // an agent it cannot parse — so the entry is written and nothing
            // ever starts.
            let plist = plist_content(Path::new("/Users/A&B/nexa.app/nexa"));
            assert!(
                plist.contains("<string>/Users/A&amp;B/nexa.app/nexa</string>"),
                "{plist}"
            );
            // And the `<` and `>` of a path are escaped the same way.
            let plist = plist_content(Path::new("/Users/<a>/nexa"));
            assert!(
                plist.contains("<string>/Users/&lt;a&gt;/nexa</string>"),
                "{plist}"
            );
        }
    }
}

// -- Linux -----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::{current_exe, ENTRY_NAME};
    use crate::error::{codes, AppError};
    use std::path::PathBuf;

    /// Where the desktop session looks for what to start with it.
    ///
    /// The code is the one the caller reports a failure under: not finding
    /// the entry and not being able to write it are different failures.
    fn desktop_path(code: &str) -> Result<PathBuf, AppError> {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            AppError::with_detail(
                code,
                "HOME is not set, so there is no place to put an autostart entry",
            )
        })?;
        Ok(home
            .join(".config")
            .join("autostart")
            .join(format!("{ENTRY_NAME}.desktop")))
    }

    pub fn is_enabled() -> Result<bool, AppError> {
        let path = desktop_path(codes::AUTOSTART_READ_FAILED)?;
        // `metadata` rather than `exists`: the latter answers "no" for an
        // entry that cannot be read as well as for one that is not there,
        // and a read failure is not the same answer as "off".
        match std::fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(AppError::with_detail(
                codes::AUTOSTART_READ_FAILED,
                format!("the autostart entry could not be read: {e}"),
            )),
        }
    }

    pub fn set_enabled(enabled: bool) -> Result<(), AppError> {
        let path = desktop_path(codes::AUTOSTART_WRITE_FAILED)?;
        if !enabled {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the autostart entry could not be removed: {e}"),
                )),
            }
        } else {
            let exe = current_exe()?;
            let content = desktop_content(&exe);
            let dir = path.parent().expect("the path has a parent");
            std::fs::create_dir_all(dir).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the autostart directory could not be created: {e}"),
                )
            })?;
            std::fs::write(&path, content).map_err(|e| {
                AppError::with_detail(
                    codes::AUTOSTART_WRITE_FAILED,
                    format!("the autostart entry could not be written: {e}"),
                )
            })?;
            Ok(())
        }
    }

    /// The entry, in the format the desktop entry specification defines.
    ///
    /// `X-GNOME-Autostart-enabled` is what GNOME reads; the specification
    /// itself only says the file is honoured, so the other desktops need
    /// nothing more than the file.
    fn desktop_content(exe: &std::path::Path) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name={ENTRY_NAME}\n\
             Exec={} {}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n",
            super::quote_argument(exe),
            super::BACKGROUND_FLAG,
        )
    }
}

// -- anything else ---------------------------------------------------------------------

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod platform {
    use crate::error::{codes, AppError};

    pub fn is_enabled() -> Result<bool, AppError> {
        Err(AppError::new(codes::AUTOSTART_UNSUPPORTED_PLATFORM))
    }

    pub fn set_enabled(_enabled: bool) -> Result<(), AppError> {
        Err(AppError::new(codes::AUTOSTART_UNSUPPORTED_PLATFORM))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_background_flag_is_a_word_the_launcher_can_pass() {
        // It travels through a registry value, a plist array and a desktop
        // entry's `Exec` line, so it has to be a single argument with no
        // spaces in it.
        assert!(!BACKGROUND_FLAG.contains(' '));
        assert!(BACKGROUND_FLAG.starts_with("--"));
    }

    #[test]
    fn the_entry_name_is_one_word() {
        // The same name appears in a registry value, a file name and a plist
        // label; a space in it would need quoting in two of the three.
        assert!(!ENTRY_NAME.contains(' '));
    }

    /// `reg query` cannot tell "the value is not there" from "the key cannot
    /// be read", so the key and its parent are asked as well.
    #[test]
    fn a_registry_that_answers_tells_whether_the_entry_is_there() {
        // The value is there: the entry is on.
        assert!(registry_answers(true, true, true).unwrap());

        // The value is not there, and the key can be read: the entry is not
        // on. This is the ordinary answer before the entry was ever written.
        assert!(!registry_answers(false, true, true).unwrap());

        // The key is not there either, but its parent is: there is nowhere
        // for the entry to be, so "off" is the truth.
        assert!(!registry_answers(false, false, true).unwrap());

        // Nothing could be read: a failure to read is not "off", because the
        // entry may well be there.
        let error = registry_answers(false, false, false).unwrap_err();
        assert_eq!(error.code, crate::error::codes::AUTOSTART_READ_FAILED);
    }

    /// How the `Exec` line of a desktop entry carries a path.
    mod quoting {
        use super::quote_argument;
        use std::path::Path;

        #[test]
        fn a_path_with_a_space_in_it_is_quoted() {
            // The `Exec` line is read as a command, so an unquoted space would
            // end the program name early and the entry would start nothing.
            assert_eq!(
                quote_argument(Path::new("/home/a b/nexa")),
                "\"/home/a b/nexa\""
            );
        }

        #[test]
        fn a_path_without_a_space_in_it_is_left_alone() {
            // Quoting is only needed where it changes the meaning; adding it
            // everywhere would make every entry look like a special case.
            assert_eq!(quote_argument(Path::new("/home/ab/nexa")), "/home/ab/nexa");
        }

        #[test]
        fn a_path_with_a_reserved_character_in_it_is_quoted() {
            // The `Exec` line is read as a command, so an unquoted `&` ends the
            // program name early — the entry then starts `/home/a` and nothing
            // else. The specification reserves a whole set of characters, not
            // the space alone.
            assert_eq!(
                quote_argument(Path::new("/home/a&b/nexa")),
                "\"/home/a&b/nexa\""
            );
            assert_eq!(
                quote_argument(Path::new("/home/a;b/nexa")),
                "\"/home/a;b/nexa\""
            );
        }

        #[test]
        fn a_quote_in_a_quoted_path_is_escaped() {
            // Inside the quotes, four characters need an escape of their own.
            assert_eq!(
                quote_argument(Path::new("/home/a\"b/nexa")),
                "\"/home/a\\\"b/nexa\""
            );
            assert_eq!(
                quote_argument(Path::new("/home/a$b/nexa")),
                "\"/home/a\\$b/nexa\""
            );
        }

        #[test]
        fn a_backslash_in_a_quoted_path_is_escaped_twice_over() {
            // The escape rule for a string value runs before the quoting rule,
            // so a literal backslash is two escapes of its own: four
            // backslashes in the file.
            assert_eq!(
                quote_argument(Path::new("/home/a\\b/nexa")),
                "\"/home/a\\\\\\\\b/nexa\""
            );
        }

        #[test]
        fn a_tilde_or_a_pipe_in_a_path_is_quoted() {
            // The specification reserves both, so a path carrying one is
            // quoted like any other.
            assert_eq!(
                quote_argument(Path::new("/home/a~b/nexa")),
                "\"/home/a~b/nexa\""
            );
            assert_eq!(
                quote_argument(Path::new("/home/a|b/nexa")),
                "\"/home/a|b/nexa\""
            );
        }

        #[test]
        fn a_percentage_in_a_path_is_escaped() {
            // A `%` is a field code otherwise, and the specification expands
            // those before the program sees the path — so a literal one is
            // written `%%`, quoted or not.
            assert_eq!(
                quote_argument(Path::new("/home/a%b/nexa")),
                "/home/a%%b/nexa"
            );
            assert_eq!(
                quote_argument(Path::new("/home/a b%c/nexa")),
                "\"/home/a b%%c/nexa\""
            );
        }
    }

    /// The launch flag is read off the process's own arguments, and it has to
    /// be matched exactly: an argument that merely starts with it is somebody
    /// else's.
    #[test]
    fn the_flag_is_matched_exactly() {
        let flag = std::ffi::OsStr::new(BACKGROUND_FLAG);
        let present = std::env::args_os().any(|arg| arg == flag);
        assert!(present == is_background_launch());
    }
}

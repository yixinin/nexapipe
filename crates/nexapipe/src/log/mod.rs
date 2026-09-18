//! Logging setup.
//!
//! Two streams are written here:
//!
//! * the regular `tracing` log (everything the program emits), which goes to
//!   stdout and, when `[log] file = true`, to `<dir>/nexapipe.log`;
//! * the access log (one line per proxied request) in `<dir>/access.log`.
//!
//! Both files are appended to, rotate on a schedule and/or by size, and keep a
//! bounded number of rotated copies, so a long running container cannot fill the
//! disk. Writes are synchronous and flushed per line: `tail -f` works and logs
//! that were emitted before an `std::process::exit` are never lost.

use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogConfig;

/// Timestamp format of every log line, in local time.
const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";

/// Overrides `[log] dir`; convenient inside containers.
const LOG_DIR_ENV: &str = "NEXAPIPE_LOG_DIR";

/// Install the global logger and the access logger.
///
/// Everything that can go wrong here (unwritable log directory, a logger that
/// was already installed) degrades to stdout logging instead of aborting: a
/// misconfigured `[log]` section must not keep the proxy from starting.
pub fn init(config: Option<&LogConfig>, debug: bool) {
    let settings = Settings::from_config(config);
    let filter = EnvFilter::new(format!("nexapipe={}", if debug { "debug" } else { "info" }));

    let log_sink = open_sink(&settings, &settings.file_name);
    let access_sink = if settings.access_log {
        open_sink(&settings, &settings.access_file_name)
    } else {
        None
    };

    let console = settings.console || log_sink.is_none();
    if !settings.console && log_sink.is_none() {
        eprintln!(
            "nexapipe: [log] console = false but no log file is available, keeping console output"
        );
    }

    let registry = tracing_subscriber::registry().with(filter);
    let installed = match (console, log_sink.clone()) {
        (true, Some(sink)) => registry
            .with(console_layer())
            .with(file_layer(sink))
            .try_init(),
        (true, None) => registry.with(console_layer()).try_init(),
        (false, Some(sink)) => registry.with(file_layer(sink)).try_init(),
        // Unreachable: `console` is forced on when there is no file to write to.
        (false, None) => registry.with(console_layer()).try_init(),
    };

    if installed.is_err() {
        eprintln!("nexapipe: a global logger is already installed, keeping it");
        return;
    }

    init_access_logger(settings.access_log, access_sink.clone());

    if let Some(sink) = &log_sink {
        let keep = if settings.max_files == 0 {
            "unlimited".to_string()
        } else {
            settings.max_files.to_string()
        };
        tracing::info!(
            "Logging to {} ({} rotation, keeping {} rotated file(s))",
            sink.path().display(),
            settings.rotation.label(),
            keep
        );
        if let Some(access) = &access_sink {
            tracing::info!("Access log: {}", access.path().display());
        }
    }
}

fn console_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .with_target(false)
        .with_timer(ChronoLocal::new(TIME_FORMAT.to_string()))
}

fn file_layer<S>(sink: FileSink) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .with_target(false)
        // No colour escape codes in the file.
        .with_ansi(false)
        .with_timer(ChronoLocal::new(TIME_FORMAT.to_string()))
        .with_writer(sink)
}

/// Open one of the log files, reporting a failure on stderr instead of aborting.
fn open_sink(settings: &Settings, file_name: &str) -> Option<FileSink> {
    if !settings.write_file {
        return None;
    }

    match settings.file_sink(file_name) {
        Ok(sink) => Some(sink),
        Err(err) => {
            eprintln!(
                "nexapipe: cannot open log file {}/{}: {}",
                settings.dir.display(),
                file_name,
                err
            );
            None
        }
    }
}

/// Resolved `[log]` settings, with the defaults applied.
#[derive(Debug, Clone)]
struct Settings {
    write_file: bool,
    dir: PathBuf,
    file_name: String,
    access_log: bool,
    access_file_name: String,
    rotation: Rotation,
    max_size_mb: u64,
    max_files: usize,
    console: bool,
}

impl Settings {
    fn from_config(config: Option<&LogConfig>) -> Self {
        let config = config.cloned().unwrap_or_default();

        let dir = std::env::var(LOG_DIR_ENV)
            .ok()
            .filter(|dir| !dir.trim().is_empty())
            .or_else(|| config.dir.clone())
            .unwrap_or_else(|| "./logs".to_string());

        Self {
            write_file: config.file.unwrap_or(true),
            dir: PathBuf::from(dir),
            file_name: config
                .file_name
                .unwrap_or_else(|| "nexapipe.log".to_string()),
            access_log: config.access_log.unwrap_or(true),
            access_file_name: config
                .access_log_file_name
                .unwrap_or_else(|| "access.log".to_string()),
            rotation: config
                .rotation
                .as_deref()
                .map(Rotation::parse)
                .unwrap_or(Rotation::Daily),
            max_size_mb: config.max_size_mb.unwrap_or(0),
            max_files: config.max_files.unwrap_or(14),
            console: config.console.unwrap_or(true),
        }
    }

    fn file_sink(&self, file_name: &str) -> io::Result<FileSink> {
        FileSink::new(
            &self.dir,
            file_name,
            self.rotation,
            self.max_size_mb,
            self.max_files,
        )
    }
}

/// When a log file is rolled over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rotation {
    Never,
    Hourly,
    Daily,
}

impl Rotation {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "never" | "none" | "off" => Self::Never,
            "hourly" | "hour" => Self::Hourly,
            _ => Self::Daily,
        }
    }

    /// Identifier of the current rotation bucket, `None` when time based
    /// rotation is disabled.
    fn stamp(&self) -> Option<String> {
        match self {
            Self::Never => None,
            Self::Hourly => Some(Local::now().format("%Y-%m-%d-%H").to_string()),
            Self::Daily => Some(Local::now().format("%Y-%m-%d").to_string()),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
        }
    }
}

/// A shared, self-rotating log file. Cloning is cheap: every clone writes to the
/// same file, which is what [`MakeWriter`] needs for each `tracing` event.
#[derive(Clone)]
pub struct FileSink {
    state: Arc<Mutex<SinkState>>,
}

struct SinkState {
    /// Path of the active file; rotated copies live next to it.
    path: PathBuf,
    file: Option<File>,
    rotation: Rotation,
    /// Bucket the active file belongs to.
    stamp: Option<String>,
    /// Bytes in the active file so far.
    written: u64,
    /// Rotate once the active file would exceed this (0 = time based only).
    max_bytes: u64,
    /// Rotated copies to keep (0 = keep all).
    max_files: usize,
    /// Whether the last failure was already reported on stderr.
    reported: bool,
}

impl FileSink {
    fn new(
        dir: &Path,
        name: &str,
        rotation: Rotation,
        max_size_mb: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        fs::create_dir_all(dir)?;

        let path = dir.join(name);
        let file = open_append(&path)?;
        // The file is opened in append mode, so carry on counting where the
        // previous run stopped.
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self {
            state: Arc::new(Mutex::new(SinkState {
                path,
                file: Some(file),
                rotation,
                stamp: rotation.stamp(),
                written,
                max_bytes: max_size_mb.saturating_mul(1024 * 1024),
                max_files,
                reported: false,
            })),
        })
    }

    /// Path of the active file.
    pub fn path(&self) -> PathBuf {
        self.lock().path.clone()
    }

    /// Append one line, adding a trailing newline when missing.
    pub fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        if !line.ends_with('\n') {
            buf.push(b'\n');
        }

        let _ = self.lock().append(&buf);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SinkState> {
        // A panic somewhere else must not take logging down with it.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SinkState {
    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.rotate_if_needed(buf.len());

        let result = match self.file.as_mut() {
            Some(file) => file.write_all(buf).and_then(|()| file.flush()),
            None => Err(io::Error::other("log file is not open")),
        };

        match result {
            Ok(()) => {
                self.written += buf.len() as u64;
                self.reported = false;
                Ok(())
            }
            Err(err) => {
                // Report once and stay quiet afterwards: a full disk must not
                // turn every log line into another stderr message.
                if !self.reported {
                    eprintln!("nexapipe: failed to write {}: {}", self.path.display(), err);
                    self.reported = true;
                }
                // The file may have been removed or replaced behind our back
                // (host side rotation, `docker compose down`, ...): reopen it.
                self.file = open_append(&self.path).ok();
                Err(err)
            }
        }
    }

    fn rotate_if_needed(&mut self, incoming: usize) {
        let by_size = self.max_bytes > 0
            && self.written > 0
            && self.written.saturating_add(incoming as u64) > self.max_bytes;
        let by_time = self
            .rotation
            .stamp()
            .is_some_and(|stamp| self.stamp.as_deref() != Some(stamp.as_str()));

        if by_size || by_time {
            self.rotate();
        }
    }

    /// Rename the active file to `<stem>.<stamp>.<ext>` and start a fresh one.
    ///
    /// Failures are reported on stderr and never propagate: dropping a log line
    /// because rotation failed would be worse than a mixed up file.
    fn rotate(&mut self) {
        let stamp = self
            .rotation
            .stamp()
            .unwrap_or_else(|| Local::now().format("%Y-%m-%d-%H%M%S").to_string());
        let rotated = rotated_path(&self.path, &stamp);

        // Windows refuses to rename a file that is still open.
        drop(self.file.take());
        let renamed = fs::rename(&self.path, &rotated);
        self.file = open_append(&self.path).ok();

        match renamed {
            Ok(()) => {
                self.written = 0;
                self.stamp = self.rotation.stamp();
                prune_rotated_files(&self.path, self.max_files);
            }
            Err(err) => {
                if !self.reported {
                    eprintln!(
                        "nexapipe: failed to rotate {}: {}",
                        self.path.display(),
                        err
                    );
                    self.reported = true;
                }
                // Do not retry the same rotation on every following line.
                self.max_bytes = 0;
                self.stamp = self.rotation.stamp();
            }
        }
    }
}

/// Writer handed to `tracing` for every event; writes into the shared [`FileSink`].
pub struct SinkWriter {
    sink: FileSink,
}

impl Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sink.lock().append(buf) {
            Ok(()) => Ok(buf.len()),
            // `tracing` swallows writer errors, so reporting the failure instead
            // of pretending the write succeeded is what keeps it visible.
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.sink.lock().file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for FileSink {
    type Writer = SinkWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SinkWriter { sink: self.clone() }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// `<dir>/<stem>.<stamp>.<ext>`, with a counter appended when that name is taken.
fn rotated_path(active: &Path, stamp: &str) -> PathBuf {
    let dir = active.parent().unwrap_or_else(|| Path::new("."));
    let stem = active
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("nexapipe");
    let ext = active.extension().and_then(|ext| ext.to_str());

    let named = |suffix: &str| match ext {
        Some(ext) => dir.join(format!("{}.{}.{}", stem, suffix, ext)),
        None => dir.join(format!("{}.{}", stem, suffix)),
    };

    let mut candidate = named(stamp);
    let mut counter = 1;
    while candidate.exists() {
        candidate = named(&format!("{}-{}", stamp, counter));
        counter += 1;
    }
    candidate
}

/// Keep at most `keep` rotated files for `active`, deleting the oldest first.
fn prune_rotated_files(active: &Path, keep: usize) {
    if keep == 0 {
        return;
    }

    let Some(active_name) = active.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Some(dir) = active.parent() else {
        return;
    };
    let prefix = format!(
        "{}.",
        active
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(active_name)
    );
    let suffix = active
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext));

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    let mut rotated: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        // Only ever touch files this sink created: `<stem>.<stamp>.<ext>`.
        if name == active_name || !name.starts_with(&prefix) {
            continue;
        }
        if let Some(suffix) = &suffix
            && !name.ends_with(suffix.as_str())
        {
            continue;
        }

        let modified = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        rotated.push((modified, path));
    }

    if rotated.len() <= keep {
        return;
    }

    rotated.sort_by_key(|(modified, _)| *modified);
    for (_, path) in rotated.iter().take(rotated.len() - keep) {
        let _ = fs::remove_file(path);
    }
}

/// Access log: one line per proxied request, in Apache-ish common log format.
struct AccessLogger {
    enabled: bool,
    file: Option<FileSink>,
}

/// `None` until [`init`] ran, so embedders keep the stdout-only behaviour.
static ACCESS_LOGGER: Mutex<Option<AccessLogger>> = Mutex::new(None);

fn init_access_logger(enabled: bool, file: Option<FileSink>) {
    let mut logger = ACCESS_LOGGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *logger = Some(AccessLogger { enabled, file });
}

pub fn log_access(
    remote_addr: &str,
    method: &str,
    uri: &str,
    status: u16,
    duration_ms: u64,
    bytes_sent: usize,
) {
    let line = format!(
        "{} - - [{}] \"{} {}\" {} {} {}ms",
        remote_addr,
        Local::now().format("%d/%b/%Y:%H:%M:%S %z"),
        method,
        uri,
        status,
        bytes_sent,
        duration_ms
    );

    {
        let logger = ACCESS_LOGGER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match logger.as_ref() {
            // Not configured (library embedder): keep printing to stdout.
            None => println!("{}", line),
            Some(logger) if !logger.enabled => {}
            Some(logger) => match &logger.file {
                Some(sink) => sink.write_line(&line),
                None => println!("{}", line),
            },
        }
    }

    tracing::info!(
        "Access: {} {} {} {} {}ms",
        remote_addr,
        method,
        uri,
        status,
        duration_ms
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte level size budget, which the public API only exposes in MiB.
    fn sink_with(dir: &Path, name: &str, max_bytes: u64, max_files: usize) -> FileSink {
        let path = dir.join(name);
        let file = open_append(&path).unwrap();

        FileSink {
            state: Arc::new(Mutex::new(SinkState {
                path,
                file: Some(file),
                rotation: Rotation::Never,
                stamp: None,
                written: 0,
                max_bytes,
                max_files,
                reported: false,
            })),
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    fn rotated(dir: &Path, active: &str) -> Vec<String> {
        names(dir)
            .into_iter()
            .filter(|name| name != active)
            .collect()
    }

    #[test]
    fn appends_lines_to_the_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let sink = FileSink::new(dir.path(), "test.log", Rotation::Daily, 0, 14).unwrap();

        sink.write_line("first");
        sink.write_line("second\n");

        assert_eq!(
            fs::read_to_string(dir.path().join("test.log")).unwrap(),
            "first\nsecond\n"
        );
        assert!(names(dir.path()).contains(&"test.log".to_string()));
    }

    #[test]
    fn rotates_once_the_size_budget_is_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink_with(dir.path(), "test.log", 8, 1);

        sink.write_line("aaaa"); // 5 bytes, still under the budget
        sink.write_line("bbbb"); // would exceed it: rotate first

        assert_eq!(
            fs::read_to_string(dir.path().join("test.log")).unwrap(),
            "bbbb\n"
        );

        let rotated = rotated(dir.path(), "test.log");
        assert_eq!(rotated.len(), 1);
        assert!(rotated[0].starts_with("test."), "{:?}", rotated);
        assert!(rotated[0].ends_with(".log"), "{:?}", rotated);
        assert_eq!(
            fs::read_to_string(dir.path().join(&rotated[0])).unwrap(),
            "aaaa\n"
        );
    }

    #[test]
    fn keeps_only_the_configured_number_of_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink_with(dir.path(), "test.log", 1, 2);

        for i in 0..6 {
            sink.write_line(&i.to_string());
        }

        assert_eq!(rotated(dir.path(), "test.log").len(), 2);
    }

    #[test]
    fn parses_rotation_names() {
        assert_eq!(Rotation::parse("hourly"), Rotation::Hourly);
        assert_eq!(Rotation::parse("NEVER"), Rotation::Never);
        assert_eq!(Rotation::parse("daily"), Rotation::Daily);
        assert_eq!(Rotation::parse("something else"), Rotation::Daily);
    }
}

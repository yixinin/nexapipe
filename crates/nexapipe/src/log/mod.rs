use chrono::Local;
use std::io::Write;
use std::sync::Mutex;

pub struct AccessLogger {
    enabled: bool,
    file: Option<std::fs::File>,
}

impl AccessLogger {
    pub fn new(enabled: bool, log_file: Option<&str>) -> Self {
        let file = log_file.and_then(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        });

        AccessLogger { enabled, file }
    }

    pub fn log(
        &mut self,
        remote_addr: &str,
        method: &str,
        uri: &str,
        status: u16,
        duration_ms: u64,
        bytes_sent: usize,
    ) {
        if !self.enabled {
            return;
        }

        let now = Local::now();
        let timestamp = now.format("%d/%b/%Y:%H:%M:%S %z").to_string();

        let log_line = format!(
            "{} - - [{}] \"{} {}\" {} {} {}ms\n",
            remote_addr, timestamp, method, uri, status, bytes_sent, duration_ms
        );

        if let Some(file) = &mut self.file {
            if let Err(e) = writeln!(file, "{}", log_line) {
                tracing::error!("Failed to write access log: {}", e);
            }
        } else {
            println!("{}", log_line.trim());
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
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_ACCESS_LOGGER: Mutex<AccessLogger> = Mutex::new(AccessLogger::new(true, None));
}

pub fn init_access_logger(enabled: bool, log_file: Option<&str>) {
    let mut logger = GLOBAL_ACCESS_LOGGER.lock().unwrap();
    *logger = AccessLogger::new(enabled, log_file);
}

pub fn log_access(remote_addr: &str, method: &str, uri: &str, status: u16, duration_ms: u64, bytes_sent: usize) {
    let mut logger = GLOBAL_ACCESS_LOGGER.lock().unwrap();
    logger.log(remote_addr, method, uri, status, duration_ms, bytes_sent);
}

// Append-only JSON-line audit log. Every decision (allow or deny) gets one
// line. The line is fsync'd before the response goes back to the agent — if
// the log can't be written, the request is denied. The spec is explicit
// about this: "audit log unwritable → refuse to serve."
//
// Bodies, headers, and secrets are never logged. The path is, because
// operators need to debug; if a path contains a token, that is an upstream
// design problem, not doorman's to solve.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub struct Record<'a> {
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ms: u64,
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    /// Application protocol when it isn't plain request/response — currently
    /// only `"websocket"` for a spliced Upgrade relay. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'static str>,
}

pub struct Audit {
    path: PathBuf,
    file: Mutex<File>,
}

impl Audit {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {}: {}", parent.display(), e))?;
            }
        }
        let file = open_at(path)?;
        Ok(Audit {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    /// Serialize, append, flush, fsync. Returns an error if any of those
    /// fail; the caller must treat that as fail-closed.
    pub fn write(&self, rec: &Record<'_>) -> Result<(), String> {
        let mut buf = serde_json::to_vec(rec).map_err(|e| format!("serialize audit: {}", e))?;
        buf.push(b'\n');
        let mut f = self.file.lock().unwrap();
        f.write_all(&buf).map_err(|e| format!("write audit: {}", e))?;
        f.sync_data().map_err(|e| format!("fsync audit: {}", e))?;
        Ok(())
    }

    /// Re-open the log file at the same path. Used on SIGHUP so external
    /// rotators (logrotate, newsyslog) can move the current file aside and
    /// signal doorman to start writing to a fresh one. The previous handle
    /// is dropped after the new one is in place; in-flight writes that hold
    /// the mutex finish on the old handle and the next write lands on the
    /// new one.
    pub fn reopen(&self) -> Result<(), String> {
        let new_file = open_at(&self.path)?;
        *self.file.lock().unwrap() = new_file;
        Ok(())
    }
}

fn open_at(path: &Path) -> Result<File, String> {
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(path)
        .map_err(|e| format!("open audit log {}: {}", path.display(), e))?;
    // If the file already existed with a different mode, force 0640.
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
    Ok(f)
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_path() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let i = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "doorman_audit_test_{}_{}.log",
            std::process::id(),
            i
        ))
    }

    fn rec<'a>(decision: &'static str) -> Record<'a> {
        Record {
            ts: now_rfc3339(),
            cred: None,
            host: "h",
            method: "GET",
            path: "/",
            status: 200,
            bytes_in: 0,
            bytes_out: 0,
            ms: 0,
            decision,
            reason: None,
            protocol: None,
        }
    }

    /// Models what logrotate does: doorman writes line A, rotator moves the
    /// file aside, doorman gets SIGHUP and reopens, doorman writes line B.
    /// Result: line A in the rotated file, line B in the fresh file.
    #[test]
    fn reopen_lets_external_rotator_swap_the_file() {
        let p = tmp_path();
        let p_rotated = p.with_extension("log.1");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&p_rotated);

        let audit = Audit::open(&p).unwrap();
        audit.write(&rec("allow")).unwrap();

        std::fs::rename(&p, &p_rotated).unwrap();
        audit.reopen().unwrap();
        audit.write(&rec("deny")).unwrap();

        let rotated = std::fs::read_to_string(&p_rotated).unwrap();
        let fresh = std::fs::read_to_string(&p).unwrap();
        assert!(rotated.contains("\"decision\":\"allow\""));
        assert!(!rotated.contains("\"decision\":\"deny\""));
        assert!(fresh.contains("\"decision\":\"deny\""));
        assert!(!fresh.contains("\"decision\":\"allow\""));

        std::fs::remove_file(&p).ok();
        std::fs::remove_file(&p_rotated).ok();
    }
}

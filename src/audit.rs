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
use std::path::Path;
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
}

pub struct Audit {
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
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(path)
            .map_err(|e| format!("open audit log {}: {}", path.display(), e))?;
        // If the file already existed with a different mode, force 0640.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
        Ok(Audit {
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
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

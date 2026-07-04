// Startup posture check for issue #39.
//
// doorman's whole reason for existing is broker indirection: callers reach
// upstreams *through* the daemon and never hold the raw secret. That guarantee
// is defeated at rest when `doormand` runs under the *same* uid as the code it
// is brokering for. The config is plaintext on disk, protected only by
// filesystem DAC (mode 0400 in a 0700 dir). Those bits restrict *other* users;
// they do nothing against a process that shares the owning uid — it can just
// `open()` the file and read every secret, never touching the proxy.
//
// The service install paths avoid this by running under a dedicated,
// unprivileged account (`doorman` via the systemd unit's `User=`, `_doorman`
// via `install-darwin.sh`). The convenience tier (Homebrew, a manual
// `doormand run` from a login shell) runs as the operator's own login uid and
// has no such separation. This module emits a loud, one-time-per-start warning
// in exactly that case so the danger is visible at the moment the daemon comes
// up — not buried in a README the operator may never have read.
//
// It is a heuristic, not a proof: doorman cannot enumerate what else runs as
// its uid. It keys off the uid range each platform reserves for human login
// accounts versus dedicated service accounts — the same line the install
// tooling stays below (`_doorman` is allocated from >= 400 on macOS, `doorman`
// gets a `--system` uid < 1000 on Linux), so a correctly separated deployment
// never trips it.

/// Lowest uid that conventionally belongs to a human/interactive login account.
/// Below this line are the system/service accounts that a properly separated
/// doorman deployment uses, so they are not flagged.
///
/// - macOS: hidden service accounts (the `_name` convention) live below 500;
///   the login accounts shown at the GUI login window start at 500.
/// - Linux: `/etc/login.defs` `UID_MIN` defaults to 1000; `useradd --system`
///   allocates below it. We use the default rather than parsing login.defs to
///   keep the check dependency-free — a non-default `UID_MIN` at worst shifts
///   the boundary, and this is an advisory warning, not a gate.
const fn login_uid_min() -> u32 {
    if cfg!(target_os = "macos") {
        500
    } else {
        1000
    }
}

/// Given the effective uid the daemon is running as, return a warning to print
/// at startup when that uid looks like a human login account — the same-UID
/// exposure of issue #39 — or `None` when the uid is root or a dedicated
/// service account (the separated, safe posture).
///
/// Pure and uid-parameterized so it can be unit-tested without actually
/// dropping to another uid.
pub fn login_uid_warning(euid: u32) -> Option<String> {
    // root is a different posture entirely: the service definitions start as
    // root only so they can drop to the dedicated uid, and a root-owned config
    // read by an unprivileged daemon is the *secure* path, not this bug. Don't
    // flag it here.
    if euid == 0 {
        return None;
    }
    if euid < login_uid_min() {
        // A system/service account — this is the separated deployment doorman
        // wants operators to use. Nothing to warn about.
        return None;
    }
    Some(format!(
        "SECURITY: doorman is running as uid {euid}, which looks like a personal login \
         account.\n  \
         The config on disk is plaintext; file permissions (mode 0400) keep *other* users \
         out but do NOT\n  \
         isolate the secrets from other code running as uid {euid} — any process sharing this \
         uid (a shell,\n  \
         a cron job, an AI coding agent with file access) can read every brokered secret \
         directly and\n  \
         bypass the proxy entirely. See https://github.com/kmatzen/doorman/issues/39.\n  \
         For a real boundary, run doorman under a dedicated service uid your app code never \
         runs as:\n    \
         Linux:  the systemd unit from `doormand install-service` (User=doorman)\n    \
         macOS:  `sudo bash scripts/install-darwin.sh` (creates _doorman)\n  \
         If you accept this posture (convenience tier), pass --allow-same-uid to silence this \
         warning."
    ))
}

/// The effective uid of the current process.
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid` is always-succeeds and takes no arguments.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_not_flagged() {
        assert!(login_uid_warning(0).is_none());
    }

    #[test]
    fn service_account_is_not_flagged() {
        // Below the login-uid floor on either platform.
        assert!(login_uid_warning(400).is_none());
        assert!(login_uid_warning(login_uid_min() - 1).is_none());
    }

    #[test]
    fn login_account_is_flagged() {
        let w = login_uid_warning(login_uid_min()).expect("login uid should warn");
        assert!(w.contains("SECURITY"), "got: {}", w);
        assert!(w.contains("--allow-same-uid"), "got: {}", w);
        assert!(w.contains("issues/39"), "got: {}", w);
        // A typical Linux login uid.
        assert!(login_uid_warning(1000).is_some());
        // A typical macOS login uid.
        assert!(login_uid_warning(501).is_some());
    }
}

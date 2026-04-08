//! Preflight checks before the auditrs daemon takes over the audit netlink
//! session. Ensures that the legacy `auditd` service is not running.
//!
//! We do **not** stop `auditd` or other services automatically. If legacy
//! `auditd` appears to be running, startup fails with instructions so the
//! operator can stop it explicitly, unless daemon startup is told to skip this
//! check (CLI: `--force`).
//!
//! When systemd is available, we consult `systemctl is-active` for the unit,
//! then always run process / pid-file checks so a manually started `auditd` is
//! still detected.

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Returns an error if a legacy `auditd` instance appears to be running.
///
/// Enabling the audit subsystem and registering this process as the audit
/// endpoint is handled later in the netlink listener via `enable_events()`.
pub fn ensure_auditd_not_running() -> Result<()> {
    if use_systemd_preflight() {
        systemd_auditd_must_be_inactive()?;
    }
    proc_auditd_must_be_absent()?;
    Ok(())
}

fn use_systemd_preflight() -> bool {
    Path::new("/run/systemd/system").exists() || systemctl_binary().is_some()
}

fn systemctl_binary() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let p = dir.join("systemctl");
        p.is_file().then_some(p)
    })
}

fn systemd_auditd_must_be_inactive() -> Result<()> {
    let systemctl = systemctl_binary().context(
        "expected systemd (see /run/systemd/system) but `systemctl` was not found in PATH",
    )?;

    let output = Command::new(&systemctl)
        .args(["is-active", "--quiet", "auditd.service"])
        .output()
        .with_context(|| format!("failed to run `{}`", systemctl.display()))?;

    if output.status.success() {
        return Err(anyhow!(
            "the legacy audit daemon appears to be running (systemd reports auditd.service as active). \
             Only one userspace process should own the Linux audit session. \
             Stop auditd before starting auditrs, for example:\n\
               sudo systemctl stop auditd.service\n\
             If your distribution uses a different unit name, list units with:\n\
               systemctl list-units '*audit*'"
        ));
    }

    Ok(())
}

fn proc_auditd_must_be_absent() -> Result<()> {
    match Command::new("pidof").arg("auditd").output() {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            return Err(anyhow!(
                "a process named `auditd` is running (pidof reported PIDs). \
                 Stop the legacy audit daemon before starting auditrs so only one process owns the audit netlink session."
            ));
        }
        Ok(_) => {}
        Err(_) => {
            // No pidof (minimal systems): fall through to pid files.
        }
    }

    for path in ["/run/auditd.pid", "/var/run/auditd.pid"] {
        if let Ok(pid_str) = std::fs::read_to_string(path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if pid > 0 && unsafe { libc::kill(pid, 0) } == 0 {
                    return Err(anyhow!(
                        "legacy auditd may be running (PID {pid} from {path}). \
                         Stop it before starting auditrs."
                    ));
                }
            }
        }
    }

    Ok(())
}

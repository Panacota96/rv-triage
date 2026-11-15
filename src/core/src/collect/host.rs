//! Facts about the machine the tool runs on (FROZEN signatures for v0.1). The Windows implementations use the
//! `windows` crate and are filled in by the volatile agent; other platforms return what `std` can tell.

use serde::Serialize;
use std::path::Path;

/// What the report records about the collection host (`system.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SystemFacts {
    pub hostname: String,
    pub os_name: String,
    /// e.g. `10.0.26100` (Windows build), empty when unknown.
    pub os_build: String,
    pub boot_utc: Option<String>,
    /// e.g. `Romance Standard Time` / `UTC+01:00`.
    pub time_zone: String,
    /// The machine's clock when the facts were taken, local and UTC (RFC 3339).
    pub local_time: String,
    pub utc_time: String,
    /// `DOMAIN\user` running the tool.
    pub account: String,
    pub elevated: bool,
    /// `C:` on Windows; empty elsewhere.
    pub system_drive: String,
}

/// Whether the process runs elevated (Windows: token elevation; elsewhere: effective uid 0 is not checked and
/// `false` is returned, since only Windows live collection needs it).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// The system drive (`C:`), from `%SystemDrive%`; empty when unknown.
pub fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_default()
}

/// Whether `out` is on the same volume as `drive` (`C:`). Windows compares volume mount points
/// (`GetVolumePathNameW`); elsewhere it returns `false`.
pub fn same_volume(out: &Path, drive: &str) -> bool {
    #[cfg(windows)]
    {
        windows_impl::same_volume(out, drive)
    }
    #[cfg(not(windows))]
    {
        let _ = (out, drive);
        false
    }
}

pub fn facts() -> SystemFacts {
    #[cfg(windows)]
    {
        windows_impl::facts()
    }
    #[cfg(not(windows))]
    {
        portable_facts()
    }
}

#[allow(dead_code)]
fn portable_facts() -> SystemFacts {
    let now = chrono::Local::now();
    SystemFacts {
        hostname: crate::env::hostname(),
        os_name: std::env::consts::OS.into(),
        os_build: String::new(),
        boot_utc: None,
        time_zone: now.format("UTC%:z").to_string(),
        local_time: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        utc_time: crate::time::utc_now(),
        account: crate::env::os_user(),
        elevated: is_elevated(),
        system_drive: system_drive(),
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;

    /// STUB (volatile agent): token elevation via `GetTokenInformation(TokenElevation)`.
    pub fn is_elevated() -> bool {
        false
    }

    /// STUB (volatile agent): `GetVolumePathNameW` on both paths, compared case-insensitively.
    pub fn same_volume(out: &Path, drive: &str) -> bool {
        let out = std::path::absolute(out).unwrap_or_else(|_| out.to_path_buf());
        let s = out.display().to_string();
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        !drive.is_empty() && s.len() >= 2 && s[..2].eq_ignore_ascii_case(drive)
    }

    /// STUB (volatile agent): OS build (RtlGetVersion), boot time (GetTickCount64), time zone
    /// (GetDynamicTimeZoneInformation), account (GetUserNameExW).
    pub fn facts() -> SystemFacts {
        SystemFacts {
            elevated: is_elevated(),
            ..portable_facts()
        }
    }
}

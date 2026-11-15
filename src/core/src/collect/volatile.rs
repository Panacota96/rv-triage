//! Volatile capture from the running system (FROZEN data model for v0.1). Captured first, in order of
//! volatility: connections, processes, sessions, services. Windows only; elsewhere every list is empty and the
//! capture says it is not available.
//!
//! Each list becomes one package file (`volatile/<name>.json`), pretty JSON with sorted keys, integers and
//! strings only (no floats), so the Rust and Python verifiers agree.

use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub start_utc: Option<String>,
    /// `DOMAIN\user`, when the process token is readable.
    pub user: Option<String>,
    /// SHA-256 of the executable on disk, when it is readable (read-only, normal file API).
    pub exe_sha256: Option<String>,
    /// Why some fields are missing (e.g. `access denied`), empty when complete.
    pub note: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Connection {
    /// `tcp`, `tcp6`, `udp`, `udp6`
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    /// Empty for UDP.
    pub remote_address: String,
    pub remote_port: u16,
    /// `LISTEN`, `ESTABLISHED`, ... (TCP); empty for UDP.
    pub state: String,
    pub pid: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Session {
    pub session_id: u32,
    /// `Active`, `Disconnected`, ...
    pub state: String,
    pub user: Option<String>,
    pub station: String,
    pub client_name: Option<String>,
    pub logon_utc: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Service {
    pub name: String,
    pub display_name: String,
    /// `Running`, `Stopped`, ...
    pub state: String,
    /// `Automatic`, `Manual`, `Disabled`, ...
    pub start_type: String,
    pub binary_path: Option<String>,
    pub account: Option<String>,
    pub pid: u32,
}

/// Part of a capture that was incomplete: `what` = processes | connections | sessions | services.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Partial {
    pub what: String,
    /// Entries with missing fields (or the whole list when `of` = 0).
    pub incomplete: u64,
    pub of: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Capture {
    pub available: bool,
    pub started_utc: String,
    pub finished_utc: String,
    pub processes: Vec<Process>,
    pub connections: Vec<Connection>,
    pub sessions: Vec<Session>,
    pub services: Vec<Service>,
    pub partial: Vec<Partial>,
}

impl Capture {
    /// The package files: (name, pretty JSON bytes), in capture order.
    pub fn files(&self) -> Vec<(&'static str, Vec<u8>)> {
        fn j<T: Serialize>(v: &T) -> Vec<u8> {
            let mut b = serde_json::to_vec_pretty(v).unwrap_or_default();
            b.push(b'\n');
            b
        }
        vec![
            ("connections.json", j(&self.connections)),
            ("processes.json", j(&self.processes)),
            ("sessions.json", j(&self.sessions)),
            ("services.json", j(&self.services)),
        ]
    }

    /// The incomplete parts of the list stored in `file` (`processes.json` → `processes`).
    pub fn partial_for(&self, file: &str) -> Vec<&Partial> {
        let what = file.trim_end_matches(".json");
        self.partial.iter().filter(|p| p.what == what).collect()
    }
}

/// Captures the volatile state. `cancel` is checked between lists.
pub fn capture(cancel: &std::sync::atomic::AtomicBool) -> Capture {
    let started_utc = crate::time::utc_now();
    #[cfg(windows)]
    let mut c = windows_impl::capture(cancel);
    #[cfg(not(windows))]
    let mut c = {
        let _ = cancel;
        Capture::default()
    };
    c.started_utc = started_utc;
    c.finished_utc = crate::time::utc_now();
    c
}

#[cfg(windows)]
mod windows_impl {
    use super::*;

    /// STUB (volatile agent): GetExtendedTcpTable/GetExtendedUdpTable, CreateToolhelp32Snapshot + process
    /// token/PEB for user and command line, WTSEnumerateSessionsW, EnumServicesStatusExW.
    pub fn capture(_cancel: &std::sync::atomic::AtomicBool) -> Capture {
        Capture {
            available: true,
            partial: ["connections", "processes", "sessions", "services"]
                .iter()
                .map(|w| Partial {
                    what: (*w).into(),
                    incomplete: 0,
                    of: 0,
                    reason: "not implemented yet".into(),
                })
                .collect(),
            ..Capture::default()
        }
    }
}

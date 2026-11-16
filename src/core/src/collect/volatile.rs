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
    //! Read-only Win32 enumeration. Nothing is written to the machine: no files, no registry, no ETW/WMI
    //! sessions, no services. Executables are hashed with the normal read-only file API.
    use super::*;
    use crate::collect::host::windows_impl::{
        Handle, filetime_utc, from_pwstr, from_wide, last_error, os_error, wide,
    };
    use crate::hash::{HashAlgo, hash_reader};
    use std::collections::{BTreeSet, HashMap};
    use std::ffi::{OsStr, c_void};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessCommandLineInformation,
    };
    use windows_sys::Win32::Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, FILETIME, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, UNICODE_STRING,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, LookupAccountSidW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS, WTS_SESSION_INFOW, WTSClientName, WTSDomainName,
        WTSEnumerateSessionsW, WTSFreeMemory, WTSINFOW, WTSQuerySessionInformationW,
        WTSSessionInfo, WTSUserName,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW,
        SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_DELAYED_AUTO_START_INFO,
        SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    /// Executables above this size are not hashed (time on a live system matters more).
    const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
    const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
    const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;

    /// Closes a service-control-manager handle on drop.
    struct ScHandle(SC_HANDLE);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle was returned open by OpenSCManagerW/OpenServiceW and is closed once, here.
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    /// Frees memory returned by the WTS API on drop.
    struct WtsMem(*mut c_void);
    impl Drop for WtsMem {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was allocated by a WTS API call and is freed once, here.
                unsafe { WTSFreeMemory(self.0) };
            }
        }
    }

    fn ntstatus_text(st: i32) -> String {
        if st == STATUS_ACCESS_DENIED {
            "access denied (NTSTATUS 0xC0000022)".into()
        } else {
            format!("NTSTATUS 0x{:08X}", st as u32)
        }
    }

    /// An 8-byte aligned buffer of at least `bytes` bytes (Win32 tables hold pointers and u64s).
    fn aligned(bytes: usize) -> Vec<u64> {
        vec![0u64; bytes.div_ceil(8).max(1)]
    }

    /// The rows of a `{ dwNumEntries: u32, table: [T; 1] }` table, bounds-checked against the buffer.
    fn table_rows<Table, T>(buf: &[u64], rows_offset: usize) -> &[T] {
        let bytes = buf.len() * 8;
        debug_assert!(rows_offset < std::mem::size_of::<Table>());
        if bytes < rows_offset.max(4) {
            return &[];
        }
        // SAFETY: the buffer is at least 4 bytes and 8-byte aligned; the first field is the row count.
        let n = unsafe { *(buf.as_ptr() as *const u32) } as usize;
        let max = bytes.saturating_sub(rows_offset) / std::mem::size_of::<T>();
        let n = n.min(max);
        // SAFETY: `n` rows of T fit in the buffer after `rows_offset` (checked above); the offset keeps T's
        // alignment because it is the table's own field offset; the data was written by the API.
        unsafe {
            std::slice::from_raw_parts((buf.as_ptr() as *const u8).add(rows_offset).cast::<T>(), n)
        }
    }

    fn tcp_state(s: u32) -> &'static str {
        match s {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN",
        }
    }

    /// Port stored in network byte order in the low 16 bits of a DWORD.
    fn port(dw: u32) -> u16 {
        u16::from_be((dw & 0xffff) as u16)
    }

    fn v4(dw: u32) -> String {
        Ipv4Addr::from(dw.to_ne_bytes()).to_string()
    }

    fn v6(addr: [u8; 16], scope: u32) -> String {
        let a = Ipv6Addr::from(addr).to_string();
        if scope != 0 {
            format!("{}%{}", a, scope)
        } else {
            a
        }
    }

    /// Calls a GetExtended*Table function until the buffer is large enough.
    fn read_table(call: impl Fn(*mut c_void, &mut u32) -> u32) -> Result<Vec<u64>, String> {
        let mut size = 0u32;
        let mut buf = aligned(16);
        for _ in 0..8 {
            size = size.max((buf.len() * 8) as u32);
            let r = call(buf.as_mut_ptr().cast(), &mut size);
            match r {
                0 => return Ok(buf),
                ERROR_INSUFFICIENT_BUFFER => buf = aligned(size as usize + 4096),
                e => return Err(os_error(e)),
            }
        }
        Err("table kept growing".into())
    }

    fn connections(out: &mut Vec<Connection>) -> Vec<String> {
        let mut failed = vec![];
        let tcp = |af: u32| {
            read_table(|p, size| {
                // SAFETY: `p` points to a writable buffer of `*size` bytes; `size` is a valid in/out pointer.
                unsafe { GetExtendedTcpTable(p, size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0) }
            })
        };
        let udp = |af: u32| {
            read_table(|p, size| {
                // SAFETY: `p` points to a writable buffer of `*size` bytes; `size` is a valid in/out pointer.
                unsafe { GetExtendedUdpTable(p, size, 0, af, UDP_TABLE_OWNER_PID, 0) }
            })
        };
        match tcp(AF_INET) {
            Ok(b) => {
                let rows = table_rows::<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(
                    &b,
                    std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
                );
                out.extend(rows.iter().map(|r| Connection {
                    protocol: "tcp".into(),
                    local_address: v4(r.dwLocalAddr),
                    local_port: port(r.dwLocalPort),
                    remote_address: v4(r.dwRemoteAddr),
                    remote_port: port(r.dwRemotePort),
                    state: tcp_state(r.dwState).into(),
                    pid: r.dwOwningPid,
                }));
            }
            Err(e) => failed.push(format!("tcp: {}", e)),
        }
        match tcp(AF_INET6) {
            Ok(b) => {
                let rows = table_rows::<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(
                    &b,
                    std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
                );
                out.extend(rows.iter().map(|r| Connection {
                    protocol: "tcp6".into(),
                    local_address: v6(r.ucLocalAddr, r.dwLocalScopeId),
                    local_port: port(r.dwLocalPort),
                    remote_address: v6(r.ucRemoteAddr, r.dwRemoteScopeId),
                    remote_port: port(r.dwRemotePort),
                    state: tcp_state(r.dwState).into(),
                    pid: r.dwOwningPid,
                }));
            }
            Err(e) => failed.push(format!("tcp6: {}", e)),
        }
        match udp(AF_INET) {
            Ok(b) => {
                let rows = table_rows::<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(
                    &b,
                    std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
                );
                out.extend(rows.iter().map(|r| Connection {
                    protocol: "udp".into(),
                    local_address: v4(r.dwLocalAddr),
                    local_port: port(r.dwLocalPort),
                    pid: r.dwOwningPid,
                    ..Connection::default()
                }));
            }
            Err(e) => failed.push(format!("udp: {}", e)),
        }
        match udp(AF_INET6) {
            Ok(b) => {
                let rows = table_rows::<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(
                    &b,
                    std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
                );
                out.extend(rows.iter().map(|r| Connection {
                    protocol: "udp6".into(),
                    local_address: v6(r.ucLocalAddr, r.dwLocalScopeId),
                    local_port: port(r.dwLocalPort),
                    pid: r.dwOwningPid,
                    ..Connection::default()
                }));
            }
            Err(e) => failed.push(format!("udp6: {}", e)),
        }
        out.sort_by(|a, b| {
            (
                &a.protocol,
                &a.local_address,
                a.local_port,
                &a.remote_address,
                a.remote_port,
                a.pid,
                &a.state,
            )
                .cmp(&(
                    &b.protocol,
                    &b.local_address,
                    b.local_port,
                    &b.remote_address,
                    b.remote_port,
                    b.pid,
                    &b.state,
                ))
        });
        failed
    }

    /// `S-1-5-21-...` from a binary SID (used when the account name cannot be resolved).
    pub(super) fn sid_text(sid: &[u8]) -> String {
        if sid.len() < 8 {
            return String::new();
        }
        let auth = sid[2..8].iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
        let mut s = format!("S-{}-{}", sid[0], auth);
        let n = usize::from(sid[1]);
        for i in 0..n {
            let o = 8 + i * 4;
            if o + 4 > sid.len() {
                break;
            }
            let sub = u32::from_le_bytes([sid[o], sid[o + 1], sid[o + 2], sid[o + 3]]);
            s.push_str(&format!("-{}", sub));
        }
        s
    }

    /// `DOMAIN\user` for a SID (or the SID text when the name is not mapped).
    fn account_of(sid: *mut c_void, cache: &mut HashMap<Vec<u8>, String>) -> String {
        // SAFETY: `sid` points to a valid SID inside a TOKEN_USER buffer that outlives this call.
        let len = unsafe { GetLengthSid(sid) } as usize;
        // SAFETY: GetLengthSid returned the SID's size in bytes, all readable.
        let bytes = unsafe { std::slice::from_raw_parts(sid as *const u8, len) }.to_vec();
        if let Some(n) = cache.get(&bytes) {
            return n.clone();
        }
        let mut name = vec![0u16; 256];
        let mut dom = vec![0u16; 256];
        let (mut nn, mut dn) = (name.len() as u32, dom.len() as u32);
        let mut use_ = 0i32;
        // SAFETY: both buffers are writable for the sizes passed; `sid` is valid; out pointers are valid.
        let ok = unsafe {
            LookupAccountSidW(
                null(),
                sid,
                name.as_mut_ptr(),
                &mut nn,
                dom.as_mut_ptr(),
                &mut dn,
                &mut use_,
            )
        };
        let text = if ok != 0 {
            let (n, d) = (from_wide(&name), from_wide(&dom));
            if d.is_empty() {
                n
            } else {
                format!("{}\\{}", d, n)
            }
        } else {
            sid_text(&bytes)
        };
        cache.insert(bytes, text.clone());
        text
    }

    fn process_user(h: HANDLE, cache: &mut HashMap<Vec<u8>, String>) -> Result<String, String> {
        let mut tok: HANDLE = null_mut();
        // SAFETY: `h` is an open process handle; `tok` is a valid out pointer.
        if unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut tok) } == 0 {
            return Err(last_error());
        }
        let tok = Handle(tok);
        let mut need = 0u32;
        // SAFETY: a null buffer of size 0 only asks for the required size.
        unsafe { GetTokenInformation(tok.0, TokenUser, null_mut(), 0, &mut need) };
        if need == 0 {
            return Err(last_error());
        }
        let mut buf = aligned(need as usize);
        // SAFETY: `buf` is writable for at least `need` bytes and 8-byte aligned.
        let ok = unsafe {
            GetTokenInformation(tok.0, TokenUser, buf.as_mut_ptr().cast(), need, &mut need)
        };
        if ok == 0 {
            return Err(last_error());
        }
        // SAFETY: the API wrote a TOKEN_USER at the start of the aligned buffer.
        let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        Ok(account_of(tu.User.Sid, cache))
    }

    fn exe_path(h: HANDLE) -> Result<String, String> {
        let mut buf = vec![0u16; 32_768];
        let mut n = buf.len() as u32;
        // SAFETY: `buf` is writable for `n` units; `n` is a valid in/out pointer.
        let ok =
            unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(String::from_utf16_lossy(
            &buf[..(n as usize).min(buf.len())],
        ))
    }

    fn start_time(h: HANDLE) -> Result<Option<String>, String> {
        let z = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        // SAFETY: `h` is an open process handle; all four out pointers are valid FILETIMEs.
        if unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } == 0 {
            return Err(last_error());
        }
        let t = (i64::from(c.dwHighDateTime) << 32) | i64::from(c.dwLowDateTime);
        Ok(filetime_utc(t))
    }

    /// The command line via NtQueryInformationProcess(ProcessCommandLineInformation) (Windows 8.1+): it only
    /// needs PROCESS_QUERY_LIMITED_INFORMATION and does not read the target's memory.
    fn command_line(h: HANDLE) -> Result<Option<String>, String> {
        let mut buf = aligned(2048);
        for _ in 0..4 {
            let size = (buf.len() * 8) as u32;
            let mut need = 0u32;
            // SAFETY: `buf` is writable for `size` bytes and 8-byte aligned; `need` is a valid out pointer.
            let st = unsafe {
                NtQueryInformationProcess(
                    h,
                    ProcessCommandLineInformation,
                    buf.as_mut_ptr().cast(),
                    size,
                    &mut need,
                )
            };
            if st >= 0 {
                // SAFETY: on success the buffer starts with a UNICODE_STRING.
                let us = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
                let start = buf.as_ptr() as usize;
                let end = start + buf.len() * 8;
                let p = us.Buffer as usize;
                let len = usize::from(us.Length);
                if us.Buffer.is_null() || len == 0 {
                    return Ok(None);
                }
                if p < start || p + len > end {
                    return Err("command line outside the returned buffer".into());
                }
                // SAFETY: the string lies inside `buf` (checked above) and is `len` bytes of UTF-16.
                let s = unsafe { std::slice::from_raw_parts(us.Buffer as *const u16, len / 2) };
                return Ok(Some(String::from_utf16_lossy(s)));
            }
            let grow = st == STATUS_INFO_LENGTH_MISMATCH
                || st == STATUS_BUFFER_OVERFLOW
                || st == STATUS_BUFFER_TOO_SMALL;
            if grow && need > size && need < (1 << 22) {
                buf = aligned(need as usize);
                continue;
            }
            return Err(ntstatus_text(st));
        }
        Err("command line kept growing".into())
    }

    fn hash_exe(path: &str, cancel: &AtomicBool) -> Result<String, String> {
        let io = |e: std::io::Error| match e.raw_os_error() {
            Some(c) => os_error(c as u32),
            None => format!("{:?}", e.kind()),
        };
        let f = std::fs::File::open(path).map_err(io)?;
        let len = f.metadata().map_err(io)?.len();
        if len > MAX_HASH_BYTES {
            return Err(format!("larger than 512 MiB ({} bytes), not hashed", len));
        }
        match hash_reader(f, &[HashAlgo::Sha256], |_| !cancel.load(Ordering::Relaxed))
            .map_err(io)?
        {
            Some(o) => o
                .digests
                .into_iter()
                .next()
                .map(|(_, d)| d)
                .ok_or_else(|| "no digest".to_string()),
            None => Err("cancelled".into()),
        }
    }

    fn processes(cancel: &AtomicBool, out: &mut Vec<Process>) -> Result<(), String> {
        // SAFETY: TH32CS_SNAPPROCESS with pid 0 snapshots all processes; the handle is closed by the guard.
        let snap = Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) });
        if snap.0 == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        // SAFETY: PROCESSENTRY32W is plain data; all-zero is a valid value.
        let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut entries = vec![];
        // SAFETY: the snapshot is open; `pe` has its size set.
        let mut more = unsafe { Process32FirstW(snap.0, &mut pe) } != 0;
        while more {
            entries.push((
                pe.th32ProcessID,
                pe.th32ParentProcessID,
                from_wide(&pe.szExeFile),
            ));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap.0, &mut pe) } != 0;
        }
        if entries.is_empty() {
            return Err(last_error());
        }
        let mut users = HashMap::new();
        let mut hashes: HashMap<String, Result<String, String>> = HashMap::new();
        for (pid, ppid, name) in entries {
            let mut p = Process {
                pid,
                ppid,
                name,
                ..Process::default()
            };
            let mut notes: Vec<String> = vec![];
            if pid == 0 || pid == 4 {
                // System Idle Process and System: kernel, no user-mode image, token or command line.
                p.note = String::new();
                out.push(p);
                continue;
            }
            // SAFETY: OpenProcess has no memory preconditions; a null result is handled.
            let h = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
            if h.0.is_null() {
                notes.push(format!("open process: {}", last_error()));
            } else {
                match exe_path(h.0) {
                    Ok(x) if !x.is_empty() => p.exe_path = Some(x),
                    Ok(_) => {}
                    Err(e) => notes.push(format!("exe path: {}", e)),
                }
                match start_time(h.0) {
                    Ok(t) => p.start_utc = t,
                    Err(e) => notes.push(format!("start time: {}", e)),
                }
                match process_user(h.0, &mut users) {
                    Ok(u) => p.user = Some(u),
                    Err(e) => notes.push(format!("user: {}", e)),
                }
                match command_line(h.0) {
                    Ok(c) => p.command_line = c,
                    Err(e) => notes.push(format!("command line: {}", e)),
                }
            }
            // Minimal processes (Registry, Memory Compression, Secure System) have no file image: no hash.
            if let Some(path) = p.exe_path.as_deref().filter(|x| x.contains('\\')) {
                let r = hashes
                    .entry(path.to_lowercase())
                    .or_insert_with(|| hash_exe(path, cancel))
                    .clone();
                match r {
                    Ok(d) => p.exe_sha256 = Some(d),
                    Err(e) => notes.push(format!("exe hash: {}", e)),
                }
            }
            p.note = notes.join("; ");
            out.push(p);
        }
        out.sort_by_key(|p| p.pid);
        Ok(())
    }

    fn session_state(s: i32) -> &'static str {
        match s {
            0 => "Active",
            1 => "Connected",
            2 => "ConnectQuery",
            3 => "Shadow",
            4 => "Disconnected",
            5 => "Idle",
            6 => "Listen",
            7 => "Reset",
            8 => "Down",
            9 => "Init",
            _ => "Unknown",
        }
    }

    /// One WTS value as raw bytes (freed before returning).
    fn wts_query(id: u32, class: WTS_INFO_CLASS) -> Result<Vec<u8>, String> {
        let mut p: *mut u16 = null_mut();
        let mut bytes = 0u32;
        // SAFETY: out pointers are valid; the returned buffer is freed by the guard.
        let ok = unsafe {
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, class, &mut p, &mut bytes)
        };
        let _g = WtsMem(p.cast());
        if ok == 0 {
            return Err(last_error());
        }
        if p.is_null() {
            return Ok(vec![]);
        }
        // SAFETY: the API returned `bytes` readable bytes at `p`.
        Ok(unsafe { std::slice::from_raw_parts(p as *const u8, bytes as usize) }.to_vec())
    }

    fn wts_text(id: u32, class: WTS_INFO_CLASS) -> Result<String, String> {
        let b = wts_query(id, class)?;
        let w: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(from_wide(&w))
    }

    fn sessions(out: &mut Vec<Session>) -> Result<u64, String> {
        let mut p: *mut WTS_SESSION_INFOW = null_mut();
        let mut n = 0u32;
        // SAFETY: out pointers are valid; the returned array is freed by the guard.
        let ok = unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut p, &mut n) };
        let _g = WtsMem(p.cast());
        if ok == 0 || p.is_null() {
            return Err(last_error());
        }
        // SAFETY: the API returned `n` WTS_SESSION_INFOW entries at `p`, valid until freed.
        let list = unsafe { std::slice::from_raw_parts(p, n as usize) };
        let mut incomplete = 0u64;
        for s in list {
            let id = s.SessionId;
            let mut missing = false;
            // SAFETY: pWinStationName is a NUL-terminated string inside the WTS buffer (or null).
            let station = unsafe { from_pwstr(s.pWinStationName) };
            let user = wts_text(id, WTSUserName)
                .map_err(|_| missing = true)
                .unwrap_or_default();
            let domain = wts_text(id, WTSDomainName)
                .map_err(|_| missing = true)
                .unwrap_or_default();
            let client = wts_text(id, WTSClientName)
                .map_err(|_| missing = true)
                .unwrap_or_default();
            let logon_utc = match wts_query(id, WTSSessionInfo) {
                Ok(b) if b.len() >= std::mem::size_of::<WTSINFOW>() => {
                    // SAFETY: the buffer holds a whole WTSINFOW (size checked); read unaligned from a copy.
                    let info = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const WTSINFOW) };
                    filetime_utc(info.LogonTime)
                }
                Ok(_) => None,
                Err(_) => {
                    missing = true;
                    None
                }
            };
            if missing {
                incomplete += 1;
            }
            out.push(Session {
                session_id: id,
                state: session_state(s.State).into(),
                user: (!user.is_empty()).then(|| {
                    if domain.is_empty() {
                        user.clone()
                    } else {
                        format!("{}\\{}", domain, user)
                    }
                }),
                station,
                client_name: (!client.is_empty()).then_some(client),
                logon_utc,
            });
        }
        out.sort_by_key(|s| s.session_id);
        Ok(incomplete)
    }

    fn service_state(s: u32) -> &'static str {
        match s {
            1 => "Stopped",
            2 => "StartPending",
            3 => "StopPending",
            4 => "Running",
            5 => "ContinuePending",
            6 => "PausePending",
            7 => "Paused",
            _ => "Unknown",
        }
    }

    fn start_type(s: u32) -> &'static str {
        match s {
            0 => "Boot",
            1 => "System",
            2 => "Automatic",
            3 => "Manual",
            4 => "Disabled",
            _ => "Unknown",
        }
    }

    /// (start type, binary path, account) from QueryServiceConfigW (+ delayed auto-start).
    fn service_config(
        scm: SC_HANDLE,
        name: &str,
    ) -> Result<(String, Option<String>, Option<String>), String> {
        let wname = wide(OsStr::new(name));
        // SAFETY: `scm` is open; `wname` is NUL-terminated; the handle is closed by the guard.
        let h = ScHandle(unsafe { OpenServiceW(scm, wname.as_ptr(), SERVICE_QUERY_CONFIG) });
        if h.0.is_null() {
            return Err(last_error());
        }
        let mut need = 0u32;
        // SAFETY: a null buffer of size 0 only asks for the required size.
        unsafe { QueryServiceConfigW(h.0, null_mut(), 0, &mut need) };
        // SAFETY: reads the thread's last error.
        let e = unsafe { GetLastError() };
        if e != ERROR_INSUFFICIENT_BUFFER || need == 0 {
            return Err(os_error(e));
        }
        let mut buf = aligned(need as usize);
        // SAFETY: `buf` is writable for `need` bytes and 8-byte aligned.
        if unsafe { QueryServiceConfigW(h.0, buf.as_mut_ptr().cast(), need, &mut need) } == 0 {
            return Err(last_error());
        }
        // SAFETY: the API wrote a QUERY_SERVICE_CONFIGW (with its strings) into `buf`.
        let c = unsafe { &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
        // SAFETY: the string pointers point inside `buf` (or are null) and are NUL-terminated.
        let (bin, acct) = unsafe {
            (
                from_pwstr(c.lpBinaryPathName),
                from_pwstr(c.lpServiceStartName),
            )
        };
        let mut st = start_type(c.dwStartType).to_string();
        if c.dwStartType == 2 {
            let mut d = SERVICE_DELAYED_AUTO_START_INFO {
                fDelayedAutostart: 0,
            };
            let mut n = 0u32;
            // SAFETY: `d` is a writable SERVICE_DELAYED_AUTO_START_INFO of the size passed.
            let ok = unsafe {
                QueryServiceConfig2W(
                    h.0,
                    SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                    (&mut d as *mut SERVICE_DELAYED_AUTO_START_INFO).cast(),
                    std::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as u32,
                    &mut n,
                )
            };
            if ok != 0 && d.fDelayedAutostart != 0 {
                st = "Automatic (delayed)".into();
            }
        }
        Ok((
            st,
            (!bin.is_empty()).then_some(bin),
            (!acct.is_empty()).then_some(acct),
        ))
    }

    fn services(out: &mut Vec<Service>) -> Result<(u64, BTreeSet<String>), String> {
        // SAFETY: null machine and database names mean the local active database; closed by the guard.
        let scm = ScHandle(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) });
        if scm.0.is_null() {
            return Err(last_error());
        }
        let mut resume = 0u32;
        let mut buf = aligned(64 * 1024);
        for _ in 0..64 {
            let size = (buf.len() * 8) as u32;
            let (mut need, mut count) = (0u32, 0u32);
            // SAFETY: `buf` is writable for `size` bytes and 8-byte aligned; out pointers are valid.
            let ok = unsafe {
                EnumServicesStatusExW(
                    scm.0,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    buf.as_mut_ptr().cast(),
                    size,
                    &mut need,
                    &mut count,
                    &mut resume,
                    null(),
                )
            };
            // SAFETY: reads the thread's last error.
            let err = if ok == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if ok == 0 && err != ERROR_MORE_DATA {
                return Err(os_error(err));
            }
            let max = buf.len() * 8 / std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
            // SAFETY: the API wrote `count` entries at the start of `buf` (capped to what fits).
            let list = unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    (count as usize).min(max),
                )
            };
            for e in list {
                // SAFETY: the name pointers point inside `buf` and are NUL-terminated.
                let (name, display_name) =
                    unsafe { (from_pwstr(e.lpServiceName), from_pwstr(e.lpDisplayName)) };
                out.push(Service {
                    name,
                    display_name,
                    state: service_state(e.ServiceStatusProcess.dwCurrentState).into(),
                    pid: e.ServiceStatusProcess.dwProcessId,
                    ..Service::default()
                });
            }
            if ok != 0 {
                break;
            }
            if count == 0 {
                if need as usize <= buf.len() * 8 {
                    return Err("service list did not fit".into());
                }
                buf = aligned(need as usize);
            }
        }
        let mut incomplete = 0u64;
        let mut reasons = BTreeSet::new();
        for s in out.iter_mut() {
            match service_config(scm.0, &s.name) {
                Ok((st, bin, acct)) => {
                    s.start_type = st;
                    s.binary_path = bin;
                    s.account = acct;
                }
                Err(e) => {
                    s.start_type = "Unknown".into();
                    incomplete += 1;
                    reasons.insert(format!("configuration: {}", e));
                }
            }
        }
        out.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.name.cmp(&b.name))
        });
        Ok((incomplete, reasons))
    }

    /// Distinct reasons, at most `max`, joined for a [`Partial`].
    fn summary(reasons: impl IntoIterator<Item = String>, max: usize) -> String {
        let set: BTreeSet<String> = reasons.into_iter().collect();
        let n = set.len();
        let mut s = set.into_iter().take(max).collect::<Vec<_>>().join("; ");
        if n > max {
            s.push_str(&format!("; and {} more", n - max));
        }
        s
    }

    fn whole(what: &str, reason: String) -> Partial {
        Partial {
            what: what.into(),
            incomplete: 0,
            of: 0,
            reason,
        }
    }

    pub fn capture(cancel: &AtomicBool) -> Capture {
        let mut c = Capture {
            available: true,
            ..Capture::default()
        };
        let order = ["connections", "processes", "sessions", "services"];
        let cancelled = |c: &mut Capture, from: usize| {
            for w in &order[from..] {
                c.partial.push(whole(w, "cancelled".into()));
            }
        };

        let failed = connections(&mut c.connections);
        if failed.len() == 4 {
            c.partial.push(whole("connections", summary(failed, 4)));
        } else if !failed.is_empty() {
            c.partial.push(Partial {
                what: "connections".into(),
                incomplete: 0,
                of: c.connections.len() as u64,
                reason: format!("tables not read: {}", summary(failed, 4)),
            });
        }
        if cancel.load(Ordering::Relaxed) {
            cancelled(&mut c, 1);
            return c;
        }

        match processes(cancel, &mut c.processes) {
            Ok(()) => {
                let notes: Vec<&Process> =
                    c.processes.iter().filter(|p| !p.note.is_empty()).collect();
                if !notes.is_empty() {
                    // Group by the kind of failure ("user: access denied (error 5)"), not per process.
                    let kinds = notes
                        .iter()
                        .flat_map(|p| p.note.split("; ").map(str::to_string));
                    c.partial.push(Partial {
                        what: "processes".into(),
                        incomplete: notes.len() as u64,
                        of: c.processes.len() as u64,
                        reason: summary(kinds.map(|k| generic(&k)), 6),
                    });
                }
            }
            Err(e) => c.partial.push(whole("processes", e)),
        }
        if cancel.load(Ordering::Relaxed) {
            cancelled(&mut c, 2);
            return c;
        }

        match sessions(&mut c.sessions) {
            Ok(0) => {}
            Ok(n) => c.partial.push(Partial {
                what: "sessions".into(),
                incomplete: n,
                of: c.sessions.len() as u64,
                reason: "some session details could not be queried".into(),
            }),
            Err(e) => c.partial.push(whole("sessions", e)),
        }
        if cancel.load(Ordering::Relaxed) {
            cancelled(&mut c, 3);
            return c;
        }

        match services(&mut c.services) {
            Ok((0, _)) => {}
            Ok((n, reasons)) => c.partial.push(Partial {
                what: "services".into(),
                incomplete: n,
                of: c.services.len() as u64,
                reason: summary(reasons, 4),
            }),
            Err(e) => c.partial.push(whole("services", e)),
        }
        c
    }

    /// `exe hash: larger than 512 MiB (123 bytes), not hashed` → `exe hash: larger than 512 MiB, not hashed`
    /// so the summary groups the same failure across processes.
    fn generic(note: &str) -> String {
        match (note.find(" ("), note.rfind(" bytes)")) {
            (Some(a), Some(b)) if b > a => format!("{}{}", &note[..a], &note[b + 7..]),
            _ => note.to_string(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn formatting() {
            assert_eq!(tcp_state(2), "LISTEN");
            assert_eq!(tcp_state(5), "ESTABLISHED");
            assert_eq!(tcp_state(11), "TIME_WAIT");
            assert_eq!(port(u32::from(u16::to_be(443))), 443);
            assert_eq!(v4(u32::from_ne_bytes([127, 0, 0, 1])), "127.0.0.1");
            let mut a = [0u8; 16];
            a[15] = 1;
            assert_eq!(v6(a, 0), "::1");
            assert_eq!(
                v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 7),
                "fe80::1%7"
            );
            // S-1-5-18 (LocalSystem)
            assert_eq!(sid_text(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]), "S-1-5-18");
            assert_eq!(
                generic("exe hash: larger than 512 MiB (600000000 bytes), not hashed"),
                "exe hash: larger than 512 MiB, not hashed"
            );
            assert_eq!(
                generic("user: access denied (error 5)"),
                "user: access denied (error 5)"
            );
            assert_eq!(
                summary(["b".to_string(), "a".into(), "a".into(), "c".into()], 2),
                "a; b; and 1 more"
            );
        }

        #[test]
        fn live_capture_without_admin() {
            let cancel = AtomicBool::new(false);
            let c = super::super::capture(&cancel);
            assert!(c.available);
            assert!(c.started_utc.ends_with('Z') && c.finished_utc.ends_with('Z'));
            let me = std::process::id();
            let p = c
                .processes
                .iter()
                .find(|p| p.pid == me)
                .expect("current process listed");
            assert!(
                p.exe_path
                    .as_deref()
                    .is_some_and(|x| x.to_lowercase().ends_with(".exe"))
            );
            assert_eq!(p.exe_sha256.as_deref().map(str::len), Some(64));
            assert!(p.start_utc.is_some());
            assert!(p.user.as_deref().is_some_and(|u| !u.is_empty()));
            assert!(p.command_line.is_some());
            assert!(p.note.is_empty(), "own process complete: {}", p.note);
            assert!(c.processes.windows(2).all(|w| w[0].pid < w[1].pid));
            assert!(!c.services.is_empty());
            assert!(
                c.services
                    .iter()
                    .all(|s| !s.name.is_empty() && !s.start_type.is_empty())
            );
            assert!(
                c.sessions
                    .windows(2)
                    .all(|w| w[0].session_id <= w[1].session_id)
            );
            for x in &c.connections {
                assert!(["tcp", "tcp6", "udp", "udp6"].contains(&x.protocol.as_str()));
                assert_eq!(x.protocol.starts_with("udp"), x.state.is_empty());
            }
            // A Partial is only emitted for a list that is actually incomplete.
            for p in &c.partial {
                assert!(
                    p.of == 0 || p.incomplete > 0 || p.what == "connections",
                    "{:?}",
                    p
                );
                assert!(!p.reason.is_empty());
            }
            // Serialised output has no floats.
            for (_, b) in c.files() {
                let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
                fn no_float(v: &serde_json::Value) -> bool {
                    match v {
                        serde_json::Value::Number(n) => !n.is_f64(),
                        serde_json::Value::Array(a) => a.iter().all(no_float),
                        serde_json::Value::Object(o) => o.values().all(no_float),
                        _ => true,
                    }
                }
                assert!(no_float(&v));
            }
        }

        #[test]
        fn cancelled_before_start_stops_after_connections() {
            let cancel = AtomicBool::new(true);
            let c = capture(&cancel);
            assert!(c.processes.is_empty() && c.sessions.is_empty() && c.services.is_empty());
            let cancelled: Vec<&str> = c
                .partial
                .iter()
                .filter(|p| p.reason == "cancelled")
                .map(|p| p.what.as_str())
                .collect();
            assert_eq!(cancelled, ["processes", "sessions", "services"]);
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    #[test]
    fn not_available_elsewhere() {
        let c = super::capture(&std::sync::atomic::AtomicBool::new(false));
        assert!(!c.available);
        assert!(c.processes.is_empty());
    }
}
